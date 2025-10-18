FilePy v0.1.2 - Lightweight File Server (single-file prototype)

Requirements:
- Python 3.8+
- Install dependencies: pip install -r requirements.txt

Run:
- python file_server.py --host 0.0.0.0 --port 1966
- Optional TLS: --ssl-cert /path/cert.pem --ssl-key /path/key.pem

Features (prototype):
- File upload/download/list
- User management (sqlite), token authentication (cookie / x-auth-token)
- Simple ACLs, quotas, audit logs
- Deduplication by SHA256, optional gzip compression
- Minimal Web UI for login/upload/list
- Metrics and health endpoints for integration with monitoring

Notes & limitations:
- This is a minimal prototype for demo and testing. For production use, add robust authentication (OAuth2/OpenID), rate limiting, proper TLS termination, secure password rotation, backup/replication, and storage driver abstraction.

## 中文文档

本项目为一个轻量级单文件文件服务器，支持文件上传、下载、列表展示，用户管理、ACL 权限、日志审计等功能，并提供一个简易的 Web UI。

- 采用 **FastAPI** 作为后端框架
- 使用 **SQLite** 存储用户、文件、日志等元数据信息
- 使用 JWT 进行身份认证（可在前端使用 Cookie 或 Header 传递）
- 支持 HTTPS/TLS（推荐在生产环境使用 Nginx 或 uvicorn 的 ssl 参数）
- 通过 `requirements.txt` 一键安装依赖，Python 3.8+ 兼容

### 目录结构

```
├── FilePy.py          # 主应用文件，包含所有业务逻辑
├── requirements.txt   # 依赖列表
├── README.md          # 当前文件（含中英文版）
└── storage/           # 服务器存储目录
```

