"""
轻量级单文件文件服务器原型
特性：
- 单文件运行，后端使用 FastAPI，数据库使用 sqlite
- 用户/组/权限（ACL）、审计日志、配额、去重、压缩（可选）
- 简单 Web UI（内嵌模板）、监控/metrics、健康检查
说明：这是个原型，许多企业级功能（如真正的静态磁盘加密、复杂的分布式存储、多后端云存储驱动、深度权限继承策略等）需要在生产环境中用专门组件补充。
运行依赖见 requirements.txt
"""

import os
import io
import sqlite3
import hashlib
import uuid
import gzip
import json
import time
import asyncio
import traceback
import urllib.parse
import unicodedata

# Python 3.8 compatibility: asyncio.to_thread was added in 3.9
async def _run_in_thread(func, *args, **kwargs):
    try:
        # prefer asyncio.to_thread when available
        return await asyncio.to_thread(func, *args, **kwargs)
    except AttributeError:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: func(*args, **kwargs))
from datetime import datetime
from typing import Optional, List, Dict
from fastapi import FastAPI, Request, HTTPException, UploadFile, File, Form, Depends
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import aiofiles

# 配置
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STORAGE_DIR = os.environ.get('FS_STORAGE_DIR', os.path.join(BASE_DIR, 'storage'))
DB_PATH = os.environ.get('FS_DB_PATH', os.path.join(BASE_DIR, 'fs.db'))
ADMIN_USERNAME = os.environ.get('FS_ADMIN_USER', 'admin')
ADMIN_PASSWORD = os.environ.get('FS_ADMIN_PASS', 'admin')  # 启动后请尽快更改
ENABLE_COMPRESSION = os.environ.get('FS_ENABLE_COMPRESSION', '1') == '1'
DEFAULT_USER_QUOTA = int(os.environ.get('FS_DEFAULT_QUOTA_BYTES', str(10 * 1024 * 1024 * 1024)))  # 10GB
FS_DEBUG = os.environ.get('FS_DEBUG', '0') == '1'

os.makedirs(STORAGE_DIR, exist_ok=True)
os.makedirs(os.path.join(STORAGE_DIR, 'blobs'), exist_ok=True)

app = FastAPI(title='Lightweight File Server')

# --- 轻量 DB 层 ---

def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    c = conn.cursor()
    c.executescript('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password_hash TEXT,
        created_at INTEGER,
        quota_bytes INTEGER
    );
    CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY,
        name TEXT UNIQUE
    );
    CREATE TABLE IF NOT EXISTS user_groups (
        user_id INTEGER,
        group_id INTEGER
    );
    CREATE TABLE IF NOT EXISTS blobs (
        id INTEGER PRIMARY KEY,
        sha256 TEXT UNIQUE,
        size INTEGER,
        compressed INTEGER DEFAULT 0,
        path TEXT,
        refcount INTEGER DEFAULT 1,
        created_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY,
        name TEXT,
        parent_id INTEGER,
        is_dir INTEGER DEFAULT 0,
        blob_id INTEGER,
        owner_id INTEGER,
        created_at INTEGER,
        modified_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS acls (
        id INTEGER PRIMARY KEY,
        file_id INTEGER,
        subject_type TEXT, -- 'user' or 'group'
        subject_id INTEGER,
        perms TEXT -- e.g. 'rwx' or 'r', 'rw'
    );
    CREATE TABLE IF NOT EXISTS tokens (
        token TEXT PRIMARY KEY,
        user_id INTEGER,
        issued_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY,
        ts INTEGER,
        user_id INTEGER,
        action TEXT,
        target TEXT,
        detail TEXT
    );
    ''')
    conn.commit()
    # ensure root dir entry
    cur = conn.cursor()
    cur.execute('SELECT id FROM files WHERE id=1')
    if cur.fetchone() is None:
        now = int(time.time())
        cur.execute('INSERT INTO files (id, name, parent_id, is_dir, owner_id, created_at, modified_at) VALUES (1, ?, NULL, 1, NULL, ?, ?)'
                    , ('/', now, now))
        conn.commit()
    conn.close()

init_db()

# --- utils ---

def now_ts():
    return int(time.time())


def hash_pw(password: str, salt: Optional[bytes] = None) -> str:
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100_000)
    return salt.hex() + dk.hex()


def verify_pw(password: str, stored: str) -> bool:
    try:
        salt = bytes.fromhex(stored[:32])
        dk = stored[32:]
        check = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100_000).hex()
        return check == dk
    except Exception:
        return False


def emit_audit(user_id: Optional[int], action: str, target: str, detail: Optional[str] = None):
    conn = get_conn(); c = conn.cursor()
    c.execute('INSERT INTO audit_logs (ts, user_id, action, target, detail) VALUES (?, ?, ?, ?, ?)'
              , (now_ts(), user_id, action, target, detail))
    conn.commit(); conn.close()

# --- user management ---

def ensure_admin():
    conn = get_conn(); c = conn.cursor()
    c.execute('SELECT id FROM users WHERE username=?', (ADMIN_USERNAME,))
    if c.fetchone() is None:
        ph = hash_pw(ADMIN_PASSWORD)
        c.execute('INSERT INTO users (username, password_hash, created_at, quota_bytes) VALUES (?, ?, ?, ?)',
                  (ADMIN_USERNAME, ph, now_ts(), DEFAULT_USER_QUOTA))
        conn.commit()
    conn.close()

ensure_admin()


def create_user(username: str, password: str, quota: Optional[int] = None):
    conn = get_conn(); c = conn.cursor()
    ph = hash_pw(password)
    q = quota or DEFAULT_USER_QUOTA
    c.execute('INSERT INTO users (username, password_hash, created_at, quota_bytes) VALUES (?, ?, ?, ?)',
              (username, ph, now_ts(), q))
    conn.commit(); conn.close()


def issue_token_for_user(user_id: int) -> str:
    token = uuid.uuid4().hex
    conn = get_conn(); c = conn.cursor()
    c.execute('INSERT INTO tokens (token, user_id, issued_at) VALUES (?, ?, ?)', (token, user_id, now_ts()))
    conn.commit(); conn.close()
    return token


def get_user_by_token(token: str):
    if not token:
        return None
    conn = get_conn(); c = conn.cursor()
    c.execute('SELECT u.* FROM users u JOIN tokens t ON t.user_id=u.id WHERE t.token=?', (token,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None

async def get_current_user(request: Request):
    # token in header 'x-auth-token' or cookie
    token = request.headers.get('x-auth-token') or request.cookies.get('auth')
    user = get_user_by_token(token)
    if not user:
        raise HTTPException(status_code=401, detail='Unauthorized')
    return user

# --- blob storage (去重 + 可选压缩) ---

async def store_blob(stream, compress=ENABLE_COMPRESSION):
    # stream: bytes-like or file-like
    data = await stream.read()
    sha = hashlib.sha256(data).hexdigest()
    conn = get_conn(); c = conn.cursor()
    c.execute('SELECT * FROM blobs WHERE sha256=?', (sha,))
    existing = c.fetchone()
    if existing:
        # 增 refcount
        c.execute('UPDATE blobs SET refcount=refcount+1 WHERE id=?', (existing['id'],))
        conn.commit(); conn.close()
        return existing['id']
    # store
    blob_path = os.path.join(STORAGE_DIR, 'blobs', sha)
    compressed = 0
    if compress:
        blob_path = blob_path + '.gz'
        with gzip.open(blob_path, 'wb') as f:
            f.write(data)
        size = os.path.getsize(blob_path)
        compressed = 1
    else:
        async with aiofiles.open(blob_path, 'wb') as f:
            await f.write(data)
        size = os.path.getsize(blob_path)
    c.execute('INSERT INTO blobs (sha256, size, compressed, path, refcount, created_at) VALUES (?, ?, ?, ?, ?, ?)',
              (sha, size, compressed, blob_path, 1, now_ts()))
    conn.commit(); blob_id = c.lastrowid; conn.close()
    return blob_id


def get_blob_path(blob_id: int):
    conn = get_conn(); c = conn.cursor()
    c.execute('SELECT * FROM blobs WHERE id=?', (blob_id,))
    row = c.fetchone(); conn.close()
    if not row:
        return None
    return row['path'], bool(row['compressed']), row['size']

# --- simple permission check ---

def check_perm(user_id: int, file_id: int, perm: str) -> bool:
    # perm in 'r','w','x'
    conn = get_conn(); c = conn.cursor()
    # owner has all perms
    # owner has all perms
    c.execute('SELECT owner_id FROM files WHERE id=?', (file_id,))
    r = c.fetchone()
    if r and r['owner_id'] == user_id:
        conn.close(); return True
    # check user acl
    c.execute('SELECT perms FROM acls WHERE file_id=? AND subject_type=? AND subject_id=?', (file_id, 'user', user_id))
    row = c.fetchone()
    if row and perm in row['perms']:
        conn.close(); return True
    # check group acls
    c.execute('SELECT group_id FROM user_groups WHERE user_id=?', (user_id,))
    gids = [r['group_id'] for r in c.fetchall()]
    for gid in gids:
        c.execute('SELECT perms FROM acls WHERE file_id=? AND subject_type=? AND subject_id=?', (file_id, 'group', gid))
        rr = c.fetchone()
        if rr and perm in rr['perms']:
            conn.close(); return True
    conn.close(); return False

# --- file metadata operations ---

def list_dir(parent_id: int):
    conn = get_conn(); c = conn.cursor()
    c.execute('SELECT * FROM files WHERE parent_id=?', (parent_id,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close(); return rows

def create_file_entry(name: str, parent_id: int, is_dir: bool, owner_id: Optional[int], blob_id: Optional[int] = None):
    conn = get_conn(); c = conn.cursor()
    now = now_ts()
    c.execute('INSERT INTO files (name, parent_id, is_dir, blob_id, owner_id, created_at, modified_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
              (name, parent_id, 1 if is_dir else 0, blob_id, owner_id, now, now))
    conn.commit(); fid = c.lastrowid; conn.close(); return fid

# --- API models ---
class LoginIn(BaseModel):
    username: str
    password: str

class UserOut(BaseModel):
    id: int
    username: str
    created_at: int
    quota_bytes: int

# --- Endpoints ---

@app.post('/api/login')
async def login(data: LoginIn):
    conn = get_conn(); c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username=?', (data.username,))
    row = c.fetchone(); conn.close()
    if not row or not verify_pw(data.password, row['password_hash']):
        raise HTTPException(status_code=401, detail='Invalid credentials')
    token = issue_token_for_user(row['id'])
    emit_audit(row['id'], 'login', '/', 'successful')
    return {'token': token}

@app.post('/api/users', response_model=UserOut)
async def api_create_user(username: str = Form(...), password: str = Form(...), current=Depends(get_current_user)):
    # only admin can create users (simplified: username==ADMIN_USERNAME)
    if current['username'] != ADMIN_USERNAME:
        raise HTTPException(status_code=403, detail='Forbidden')
    create_user(username, password)
    conn = get_conn(); c = conn.cursor(); c.execute('SELECT * FROM users WHERE username=?', (username,)); r = c.fetchone(); conn.close()
    return UserOut(id=r['id'], username=r['username'], created_at=r['created_at'], quota_bytes=r['quota_bytes'])

@app.post('/api/upload')
async def upload_file(parent_id: int = Form(1), file: UploadFile = File(...), current=Depends(get_current_user)):
    try:
        # check write perm on parent
        if not check_perm(current['id'], parent_id, 'w'):
            raise HTTPException(status_code=403, detail='No write permission on target directory')
        # read file
        # wrap upload file into small async object for store_blob
        class ReadWrapper:
            def __init__(self, f): self.f = f
            async def read(self):
                # file.read() is blocking; run in thread to avoid blocking event loop
                return await _run_in_thread(self.f.read)
        blob_id = await store_blob(ReadWrapper(file.file))
        fid = create_file_entry(file.filename, parent_id, False, current['id'], blob_id)
        emit_audit(current['id'], 'upload', f'file:{fid}', file.filename)
        return {'file_id': fid}
    except Exception as e:
        tb = traceback.format_exc()
        traceback.print_exc()
        try:
            with open(os.path.join(BASE_DIR, 'upload_error.log'), 'a', encoding='utf-8') as lf:
                lf.write(tb + '\n')
        except Exception:
            pass
        if FS_DEBUG:
            return JSONResponse({'error': str(e), 'trace': tb}, status_code=500)
        else:
            return JSONResponse({'error': 'Internal server error'}, status_code=500)

@app.get('/api/list')
async def api_list(parent_id: int = 1, current=Depends(get_current_user)):
    # basic read perm check
    if not check_perm(current['id'], parent_id, 'r'):
        raise HTTPException(status_code=403, detail='No read permission')
    rows = list_dir(parent_id)
    return {'files': rows}

@app.get('/api/download/{file_id}')
async def download(file_id: int, current=Depends(get_current_user)):
    try:
        conn = get_conn(); c = conn.cursor(); c.execute('SELECT * FROM files WHERE id=?', (file_id,)); f = c.fetchone(); conn.close()
        if not f:
            raise HTTPException(status_code=404, detail='Not found')
        if f['is_dir']:
            raise HTTPException(status_code=400, detail='Is a directory')
        if not check_perm(current['id'], file_id, 'r'):
            raise HTTPException(status_code=403, detail='No read permission')
        if not f['blob_id']:
            raise HTTPException(status_code=404, detail='Blob not found')
        blob_info = get_blob_path(f['blob_id'])
        if not blob_info:
            raise HTTPException(status_code=404, detail='Blob metadata not found')
        path, compressed, size = blob_info
        if not path or not os.path.exists(path):
            raise HTTPException(status_code=404, detail='Blob file missing on disk')

        # stream file
        def iterfile():
            if compressed:
                with gzip.open(path, 'rb') as g:
                    while True:
                        chunk = g.read(8192)
                        if not chunk: break
                        yield chunk
            else:
                with open(path, 'rb') as fh:
                    while True:
                        chunk = fh.read(8192)
                        if not chunk: break
                        yield chunk

        emit_audit(current['id'], 'download', f'file:{file_id}', f['name'])
        # Build Content-Disposition safely: provide ASCII fallback and RFC5987 filename* for UTF-8 names
        def make_content_disposition(name: str) -> str:
            # try latin-1 encoding first
            try:
                name.encode('latin-1')
                return f'attachment; filename="{name}"'
            except UnicodeEncodeError:
                # if original name has any non-ASCII, use friendly fallback 'file' + original extension
                _, orig_ext = os.path.splitext(name)
                if any(ord(ch) > 127 for ch in name):
                    ascii_name = 'file' + (orig_ext or '')
                else:
                    # otherwise try to normalize and strip diacritics
                    ascii_name = unicodedata.normalize('NFKD', name).encode('ascii', 'ignore').decode('ascii')
                    base, ext = os.path.splitext(ascii_name)
                    ascii_name = (base or 'file') + (ext or orig_ext or '')
                quoted = urllib.parse.quote(name, safe='')
                header = f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quoted}"
                # debug: write computed ascii_name/header
                try:
                    with open(os.path.join(BASE_DIR, 'cd_debug.log'), 'a', encoding='utf-8') as df:
                        df.write(f"name={name!r} ascii_name={ascii_name!r} header={header}\n")
                except Exception:
                    pass
                return header

        headers = {'Content-Disposition': make_content_disposition(f['name'])}
        return StreamingResponse(iterfile(), media_type='application/octet-stream', headers=headers)
    except HTTPException:
        # re-raise HTTP exceptions for proper client codes
        raise
    except Exception as e:
        tb = traceback.format_exc()
        traceback.print_exc()
        try:
            with open(os.path.join(BASE_DIR, 'download_error.log'), 'a', encoding='utf-8') as lf:
                lf.write(tb + '\n')
        except Exception:
            pass
        if FS_DEBUG:
            return JSONResponse({'error': str(e), 'trace': tb}, status_code=500)
        else:
            return JSONResponse({'error': 'Internal server error'}, status_code=500)

@app.post('/api/delete/{file_id}')
async def delete_file(file_id: int, current=Depends(get_current_user)):
    if not check_perm(current['id'], file_id, 'w'):
        raise HTTPException(status_code=403, detail='No permission to delete')
    conn = get_conn(); c = conn.cursor()
    c.execute('SELECT * FROM files WHERE id=?', (file_id,)); f = c.fetchone()
    if not f:
        conn.close(); raise HTTPException(status_code=404)
    if f['is_dir']:
        # naive: prevent deleting root
        if f['id'] == 1:
            conn.close(); raise HTTPException(status_code=400, detail='Cannot delete root')
    blob_id = f['blob_id']
    c.execute('DELETE FROM files WHERE id=?', (file_id,))
    if blob_id:
        c.execute('UPDATE blobs SET refcount=refcount-1 WHERE id=?', (blob_id,))
        c.execute('SELECT refcount, path FROM blobs WHERE id=?', (blob_id,)); br = c.fetchone()
        if br and br['refcount'] <= 0:
            try:
                os.remove(br['path'])
            except Exception:
                pass
            c.execute('DELETE FROM blobs WHERE id=?', (blob_id,))
    conn.commit(); conn.close()
    emit_audit(current['id'], 'delete', f'file:{file_id}', f['name'])
    return {'ok': True}

@app.get('/metrics')
async def metrics(current=Depends(get_current_user)):
    # basic metrics endpoint to integrate with Nagios/Zabbix via HTTP JSON
    conn = get_conn(); c = conn.cursor()
    c.execute('SELECT COUNT(*) as cnt FROM files'); files_cnt = c.fetchone()['cnt']
    c.execute('SELECT COUNT(*) as cnt FROM blobs'); blobs_cnt = c.fetchone()['cnt']
    # disk usage
    total, used, free = shutil_disk_usage(STORAGE_DIR)
    conn.close()
    return {'files': files_cnt, 'blobs': blobs_cnt, 'disk_total': total, 'disk_used': used, 'disk_free': free}

def shutil_disk_usage(path):
    try:
        import shutil
        s = shutil.disk_usage(path)
        return s.total, s.used, s.free
    except Exception:
        return 0,0,0

@app.get('/health')
async def health():
    return {'status': 'ok', 'time': now_ts()}

# --- Web UI (极简) ---
INDEX_HTML = '''<!doctype html>
<html>
<head><title>Mini File Server</title></head>
<body>
<h1>Mini File Server</h1>
<div id="login">
<form method="post" action="/login">
Username: <input name="username" /> Password: <input name="password" type="password" />
<button type="submit">Login</button>
</form>
</div>
</body>
</html>
'''

@app.get('/', response_class=HTMLResponse)
async def index():
    return INDEX_HTML

@app.post('/login')
async def web_login(username: str = Form(...), password: str = Form(...)):
    conn = get_conn(); c = conn.cursor(); c.execute('SELECT * FROM users WHERE username=?', (username,)); r = c.fetchone(); conn.close()
    if not r or not verify_pw(password, r['password_hash']):
        return HTMLResponse('<p>登录失败</p>', status_code=401)
    token = issue_token_for_user(r['id'])
    res = HTMLResponse('<p>登录成功，跳转到文件页 <a href="/files">Files</a></p>')
    res.set_cookie('auth', token, httponly=True)
    return res

@app.get('/files', response_class=HTMLResponse)
async def web_files(request: Request, parent_id: int = 1):
    # try get current
    try:
        user = await get_current_user(request)
    except Exception:
        return HTMLResponse('<p>请先登录 <a href="/">登录</a></p>', status_code=401)
    rows = list_dir(parent_id)
    s = '<h2>Files</h2><ul>'
    for r in rows:
        name = r['name']
        if r['is_dir']:
            s += f'<li>[DIR] {name}</li>'
        else:
            s += f'<li>{name} - <a href="/api/download/{r["id"]}">下载</a></li>'
    s += '</ul>'
    s += '''<h3>Upload</h3>
    <form action="/upload" method="post" enctype="multipart/form-data">
    <input type="file" name="file" />
    <input type="hidden" name="parent_id" value="%d" />
    <button type="submit">Upload</button>
    </form>''' % parent_id
    return HTMLResponse(s)

@app.post('/upload')
async def web_upload(request: Request, file: UploadFile = File(...), parent_id: int = Form(1)):
    try:
        try:
            user = await get_current_user(request)
        except Exception:
            return HTMLResponse('<p>请先登录</p>', status_code=401)
        class ReadWrapper:
            def __init__(self, f): self.f = f
            async def read(self):
                # file.read() is blocking; run in thread to avoid blocking event loop
                return await _run_in_thread(self.f.read)
        blob_id = await store_blob(ReadWrapper(file.file))
        fid = create_file_entry(file.filename, parent_id, False, user['id'], blob_id)
        emit_audit(user['id'], 'upload_web', f'file:{fid}', file.filename)
        return JSONResponse({'file_id': fid})
    except Exception as e:
        tb = traceback.format_exc()
        traceback.print_exc()
        try:
            with open(os.path.join(BASE_DIR, 'upload_error.log'), 'a', encoding='utf-8') as lf:
                lf.write(tb + '\n')
        except Exception:
            pass
        if FS_DEBUG:
            return HTMLResponse(f'<pre>{tb}</pre>', status_code=500)
        else:
            return HTMLResponse('<p>Internal server error</p>', status_code=500)

# --- quotas (simple) ---
@app.get('/api/quota')
async def api_quota(current=Depends(get_current_user)):
    conn = get_conn(); c = conn.cursor(); c.execute('SELECT quota_bytes FROM users WHERE id=?', (current['id'],)); q = c.fetchone()['quota_bytes']
    # compute used bytes
    c.execute('SELECT SUM(b.size) as used FROM files f JOIN blobs b ON f.blob_id=b.id WHERE f.owner_id=?', (current['id'],))
    used = c.fetchone()['used'] or 0
    conn.close()
    warn = used > q * 0.9
    return {'quota': q, 'used': used, 'warn': warn}

# --- ACL endpoints ---
@app.post('/api/acl/set')
async def set_acl(file_id: int = Form(...), subject_type: str = Form(...), subject_id: int = Form(...), perms: str = Form(...), current=Depends(get_current_user)):
    # admin required for simplicity
    if current['username'] != ADMIN_USERNAME:
        raise HTTPException(status_code=403)
    conn = get_conn(); c = conn.cursor(); c.execute('INSERT INTO acls (file_id, subject_type, subject_id, perms) VALUES (?, ?, ?, ?)', (file_id, subject_type, subject_id, perms)); conn.commit(); conn.close()
    emit_audit(current['id'], 'acl_set', f'file:{file_id}', json.dumps({'subject_type': subject_type, 'subject_id': subject_id, 'perms': perms}))
    return {'ok': True}

@app.get('/api/logs')
async def get_logs(limit: int = 100, current=Depends(get_current_user)):
    if current['username'] != ADMIN_USERNAME:
        raise HTTPException(status_code=403)
    conn = get_conn(); c = conn.cursor(); c.execute('SELECT * FROM audit_logs ORDER BY ts DESC LIMIT ?', (limit,)); rows = [dict(r) for r in c.fetchall()]; conn.close()
    return {'logs': rows}

# --- startup tasks ---
@app.on_event('startup')
async def startup_event():
    # ensure admin exists
    ensure_admin()

# --- main runner ---
if __name__ == '__main__':
    import uvicorn
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=1966)
    parser.add_argument('--ssl-cert', default=None)
    parser.add_argument('--ssl-key', default=None)
    args = parser.parse_args()
    kwargs = {}
    if args.ssl_cert and args.ssl_key:
        kwargs['ssl_certfile'] = args.ssl_cert
        kwargs['ssl_keyfile'] = args.ssl_key
    uvicorn.run('file_server:app', host=args.host, port=args.port, reload=False, **kwargs)
