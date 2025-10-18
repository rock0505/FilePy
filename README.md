FilePy v0.1.1 - Lightweight File Server (single-file prototype)

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
