Set-Location -LiteralPath 'd:\PYTHON\project\FilePy'
# Stop previous process listening on 1966 (if any)
$old = Get-NetTCPConnection -LocalPort 1966 -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty OwningProcess
if ($old) {
    Write-Output "Stopping old PID $old"
    Stop-Process -Id $old -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 300
}

# Start server
$p = Start-Process -FilePath python -ArgumentList 'file_server.py','--host','0.0.0.0','--port','1966' -WorkingDirectory 'd:\PYTHON\project\FilePy' -PassThru
Write-Output "Started python PID:$($p.Id)"
Start-Sleep -Seconds 1

# create test file
'hello from test' > upload-test4.txt

# login to get token
try {
    $login = Invoke-WebRequest -Uri http://127.0.0.1:1966/api/login -Method Post -ContentType 'application/json' -Body (ConvertTo-Json @{username='admin';password='admin'}) -UseBasicParsing
    $token = (ConvertFrom-Json $login.Content).token
    Write-Output "token: $token"
} catch {
    Write-Output "Login failed: $_"
    exit 1
}

# upload using curl.exe
try {
    $upload = curl.exe -s -X POST -H "x-auth-token: $token" -F "parent_id=1" -F "file=@upload-test4.txt" http://127.0.0.1:1966/api/upload
    Write-Output "upload response: $upload"
} catch {
    Write-Output "Upload failed: $_"
}

# Query DB for last 5 files
try {
    python -c "import sqlite3,json; c=sqlite3.connect('fs.db'); c.row_factory=sqlite3.Row; cur=c.cursor(); cur.execute(\"SELECT id,name,parent_id,owner_id,created_at FROM files ORDER BY id DESC LIMIT 5\"); rows=[dict(r) for r in cur.fetchall()]; print(json.dumps(rows, ensure_ascii=False, indent=2))"
} catch {
    Write-Output "DB query failed: $_"
}

Write-Output 'run_and_test.ps1 finished. Leave this window open to see server logs.'
