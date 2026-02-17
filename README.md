# FilePy - 轻量级文件服务器

一个基于 Python + FastAPI + SQLite 的轻量级文件管理服务器，提供完整的文件管理、权限控制、安全加密等功能。

## 特性

### 核心功能
- **文件管理**：文件上传、下载、删除、重命名、移动
- **目录管理**：创建文件夹、目录浏览、面包屑导航
- **权限控制**：基于用户/组的 ACL 权限管理
- **配额管理**：磁盘使用监控、预警机制
- **日志审计**：完整的操作日志记录

### 用户界面
- **Material Design 3 风格**：现代化响应式 Web 界面
- **深色主题**：支持浅色/深色主题切换
- **多种视图**：列表视图和网格视图切换
- **移动端适配**：完美支持 PC 和移动设备访问

### 新增功能 (v0.3.0)
- **收藏功能**：收藏常用文件和文件夹，快速访问
- **最近文件**：查看最近访问、上传、下载的文件
- **用户设置**：个性化设置（主题、视图模式等）
- **用户菜单**：查看用户信息、修改密码、退出登录

### 安全特性
- **JWT 认证**：安全的 token 身份验证
- **密码加密**：bcrypt 哈希算法存储密码
- **TLS/SSL 支持**：支持 HTTPS 加密传输
- **CORS 支持**：支持跨域访问（移动端友好）

## 快速开始

### 环境要求
- Python 3.8+
- pip

### 安装

```bash
# 克隆仓库
git clone https://github.com/rock0505/FilePy.git
cd FilePy

# 安装依赖
pip install -r requirements.txt
```

### 运行

```bash
# 启动服务器
python -m app.main

# 或者使用 uvicorn 直接启动
uvicorn app.main:app --host 0.0.0.0 --port 1966
```

服务器启动后访问：`http://localhost:1966`

### 默认账户

- 用户名：`admin`
- 密码：`admin123`

### TLS/SSL 配置

```bash
# 使用自签名证书
uvicorn app.main:app --host 0.0.0.0 --port 1966 \
    --ssl-keyfile key.pem \
    --ssl-certfile cert.pem
```

## 项目结构

```
FilePy/
├── app/
│   ├── __init__.py
│   ├── main.py              # 应用入口，路由注册
│   ├── api/                 # API 路由层
│   │   ├── auth.py          # 认证相关 API
│   │   ├── files.py         # 文件操作 API
│   │   ├── favorites.py     # 收藏功能 API
│   │   ├── settings.py      # 设置功能 API
│   │   └── deps.py          # 依赖注入
│   ├── core/                # 核心模块
│   │   ├── config.py        # 配置管理
│   │   ├── database.py      # 数据库连接
│   │   └── security.py      # 安全工具（JWT、密码）
│   ├── models/              # 数据模型
│   │   ├── auth.py          # 认证相关模型
│   │   ├── file.py          # 文件相关模型
│   │   ├── user.py          # 用户相关模型
│   │   ├── favorite.py      # 收藏相关模型
│   │   └── user_settings.py # 用户设置模型
│   └── services/            # 业务逻辑层
│       ├── auth_service.py  # 认证服务
│       ├── file_service.py  # 文件服务
│       ├── favorite_service.py  # 收藏服务
│       └── settings_service.py  # 设置服务
├── templates/               # 前端模板
│   └── web_bootstrap.html  # Material Design 3 风格界面
├── tests/                   # 测试用例
│   ├── unit/               # 单元测试
│   └── integration/        # 集成测试
├── storage/                # 文件存储目录
├── filepy.db               # SQLite 数据库（自动创建）
├── requirements.txt        # 项目依赖
├── pytest.ini             # 测试配置
├── README.md              # 项目说明
└── CLAUDE.md              # 开发规范
```

## API 文档

启动服务器后访问：
- Swagger UI：`http://localhost:1966/docs`
- ReDoc：`http://localhost:1966/redoc`

### 主要 API 端点

#### 认证相关
- `POST /auth/login` - 用户登录
- `GET /auth/me` - 获取当前用户信息
- `POST /auth/change-password` - 修改密码

#### 文件操作
- `GET /files` - 获取文件列表
- `POST /files/folder` - 创建文件夹
- `POST /files/rename` - 重命名文件
- `DELETE /files/{path}` - 删除文件
- `GET /files/download/{path}` - 下载文件
- `GET /files/recent` - 获取最近文件
- `POST /files/search` - 搜索文件

#### 收藏功能
- `GET /files/favorites` - 获取收藏列表
- `POST /files/favorites` - 添加收藏
- `DELETE /files/favorites/{path}` - 取消收藏
- `GET /files/favorites/check/{path}` - 检查收藏状态

#### 用户设置
- `GET /user/settings` - 获取用户设置
- `PUT /user/settings` - 更新用户设置
- `GET /user/storage` - 获取存储信息

## 开发

### 运行测试

```bash
# 运行所有测试
pytest

# 运行测试并生成覆盖率报告
pytest --cov=app --cov-report=html

# 运行特定测试
pytest tests/unit/test_auth_service.py
```

### 代码风格

```bash
# 格式化代码
black app/ tests/

# 排序导入
isort app/ tests/

# 代码检查
pylint app/
```

## 配置

### 环境变量

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `FILEPY_SECRET_KEY` | JWT 密钥 | 必填 |
| `FILEPY_DATABASE_URL` | 数据库 URL | `sqlite:///./filepy.db` |
| `FILEPY_STORAGE_DIR` | 存储目录 | `storage` |
| `FILEPY_MAX_UPLOAD_SIZE` | 最大上传大小 | `104857600` (100MB) |

### 配置文件

支持通过 `config.ini` 文件配置：

```ini
[database]
url = sqlite:///./filepy.db

[storage]
path = storage
max_upload_size = 104857600

[security]
secret_key = your-secret-key-here
algorithm = HS256
expire_minutes = 10080
```

## 技术栈

- **后端框架**：FastAPI
- **数据库**：SQLite
- **认证**：JWT (JSON Web Tokens)
- **密码加密**：bcrypt
- **前端框架**：原生 JavaScript + Material Icons
- **测试框架**：pytest

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request！

## 更新日志

### v0.3.0 (2026-02-17)
- 新增收藏、设置、最近文件功能
- 重构为模块化架构
- 前端界面更新为 Material Design 3 风格
- 支持深色主题和多视图模式
- 添加用户菜单功能

### v0.1.2
- 初始版本
- 单文件实现
