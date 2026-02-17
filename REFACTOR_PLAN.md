# FilePy TDD + 重构计划

> 目标：将单文件架构 (2052行) 重构为模块化架构，同时建立完整的 TDD 测试框架

## 阶段概览

```
┌─────────────────────────────────────────────────────────────────┐
│  阶段 1: 测试基础设施搭建                        │
│  - 创建测试目录结构                                              │
│  - 配置 pytest                                                  │
│  - 创建测试 fixtures                                            │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  阶段 2: 核心模块提取 (单元测试先行)                            │
│  - 配置模块 (config.py)                                         │
│  - 数据库模块 (database.py)                                     │
│  - 安全模块 (security.py)                                       │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  阶段 3: 业务模块重构 (集成测试)                                │
│  - 认证模块 (auth/)                                             │
│  - 文件模块 (files/)                                            │
│  - 用户模块 (users/)                                            │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  阶段 4: API 层重构 (E2E 测试)                                  │
│  - 路由模块化                                                    │
│  - 依赖注入                                                      │
│  - 主应用入口                                                    │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  阶段 5: 质量保障                                               │
│  - 覆盖率验证 (目标 90%+)                                        │
│  - 性能测试                                                      │
│  - 文档更新                                                      │
└─────────────────────────────────────────────────────────────────┘
```

## 最终目录结构

```
FilePy/
├── app/                        # 应用主目录
│   ├── __init__.py
│   ├── main.py                 # FastAPI 应用入口
│   │
│   ├── core/                   # 核心模块
│   │   ├── __init__.py
│   │   ├── config.py           # 配置管理
│   │   ├── database.py         # 数据库连接与初始化
│   │   ├── security.py         # 安全相关 (JWT, 密码哈希)
│   │   └── limiter.py          # 速率限制配置
│   │
│   ├── models/                 # 数据模型 (Pydantic)
│   │   ├── __init__.py
│   │   ├── user.py             # 用户模型
│   │   ├── file.py             # 文件模型
│   │   ├── auth.py             # 认证模型
│   │   └── quota.py            # 配额模型
│   │
│   ├── schemas/                # 数据库 Schema (SQLAlchemy ORM)
│   │   ├── __init__.py
│   │   ├── base.py             # Base 模型
│   │   ├── user.py             # 用户表
│   │   ├── file.py             # 文件表
│   │   └── quota.py            # 配额表
│   │
│   ├── api/                    # API 路由
│   │   ├── __init__.py
│   │   ├── deps.py             # 依赖注入
│   │   ├── auth.py             # 认证路由
│   │   ├── files.py            # 文件路由
│   │   ├── users.py            # 用户管理路由
│   │   ├── quota.py            # 配额路由
│   │   └── admin.py            # 管理员路由
│   │
│   ├── services/               # 业务逻辑服务
│   │   ├── __init__.py
│   │   ├── auth_service.py     # 认证服务
│   │   ├── file_service.py     # 文件服务
│   │   ├── user_service.py     # 用户服务
│   │   └── quota_service.py    # 配额服务
│   │
│   └── utils/                  # 工具函数
│       ├── __init__.py
│       ├── file_utils.py       # 文件操作工具
│       ├── path_utils.py       # 路径处理工具
│       └── validators.py       # 验证器
│
├── tests/                      # 测试目录
│   ├── conftest.py             # pytest 配置
│   ├── __init__.py
│   │
│   ├── fixtures/               # 测试 fixtures
│   │   ├── __init__.py
│   │   ├── database.py         # 数据库 fixtures
│   │   ├── auth.py             # 认证 fixtures
│   │   ├── files.py            # 文件 fixtures
│   │   └── temp_dir.py         # 临时目录 fixtures
│   │
│   ├── unit/                   # 单元测试
│   │   ├── test_config.py
│   │   ├── test_security.py
│   │   ├── test_database.py
│   │   └── test_utils/
│   │
│   ├── integration/            # 集成测试
│   │   ├── test_auth_api.py
│   │   ├── test_files_api.py
│   │   ├── test_quota_api.py
│   │   └── test_upload_download.py
│   │
│   └── e2e/                    # 端到端测试
│       └── test_user_workflow.py
│
├── storage/                    # 文件存储目录
├── templates/                  # HTML 模板
├── config.ini                  # 配置文件
├── requirements.txt            # 依赖列表
├── pytest.ini                  # pytest 配置
├── .env.example                # 环境变量示例
├── FilePy.py                   # 旧版入口 (保留兼容)
└── run.py                      # 新版启动入口
```

## 详细变更文件清单

### 阶段 1: 测试基础设施

| 文件 | 操作 | 说明 |
|------|------|------|
| `requirements.txt` | 修改 | 添加测试依赖 |
| `pytest.ini` | 新建 | pytest 配置文件 |
| `tests/__init__.py` | 新建 | 测试包初始化 |
| `tests/conftest.py` | 新建 | pytest fixtures 配置 |
| `tests/fixtures/database.py` | 新建 | 数据库测试 fixtures |
| `tests/fixtures/auth.py` | 新建 | 认证测试 fixtures |
| `tests/fixtures/temp_dir.py` | 新建 | 临时目录 fixtures |

### 阶段 2: 核心模块

| 文件 | 操作 | 说明 |
|------|------|------|
| `app/__init__.py` | 新建 | 应用包初始化 |
| `app/core/config.py` | 新建 | 配置管理类，支持环境变量和 config.ini |
| `app/core/database.py` | 新建 | 数据库连接池，支持测试模式 |
| `app/core/security.py` | 新建 | JWT、密码哈希等安全功能 |
| `tests/unit/test_config.py` | 新建 | 配置模块单元测试 |
| `tests/unit/test_security.py` | 新建 | 安全模块单元测试 |
| `tests/unit/test_database.py` | 新建 | 数据库模块单元测试 |

### 阶段 3: 数据模型

| 文件 | 操作 | 说明 |
|------|------|------|
| `app/models/__init__.py` | 新建 | 模型包初始化 |
| `app/models/user.py` | 新建 | UserCreate, UserLogin 等模型 |
| `app/models/file.py` | 新建 | FileInfo, FileRename 等模型 |
| `app/models/auth.py` | 新建 | TokenData 模型 |
| `app/models/quota.py` | 新建 | 配额相关模型 |
| `tests/unit/test_models/` | 新建 | 模型验证测试 |

### 阶段 4: 业务服务

| 文件 | 操作 | 说明 |
|------|------|------|
| `app/services/__init__.py` | 新建 | 服务包初始化 |
| `app/services/auth_service.py` | 新建 | 认证业务逻辑 |
| `app/services/file_service.py` | 新建 | 文件操作业务逻辑 |
| `app/services/user_service.py` | 新建 | 用户管理业务逻辑 |
| `app/services/quota_service.py` | 新建 | 配额管理业务逻辑 |
| `tests/unit/test_services/` | 新建 | 服务单元测试 |
| `tests/integration/test_services/` | 新建 | 服务集成测试 |

### 阶段 5: API 路由

| 文件 | 操作 | 说明 |
|------|------|------|
| `app/api/__init__.py` | 新建 | API 包初始化 |
| `app/api/deps.py` | 新建 | 依赖注入 (get_current_user, get_db 等) |
| `app/api/auth.py` | 新建 | 认证相关路由 |
| `app/api/files.py` | 新建 | 文件操作路由 |
| `app/api/users.py` | 新建 | 用户管理路由 |
| `app/api/quota.py` | 新建 | 配额路由 |
| `app/api/admin.py` | 新建 | 管理员路由 |
| `tests/integration/test_api/` | 新建 | API 集成测试 |

### 阶段 6: 主应用入口

| 文件 | 操作 | 说明 |
|------|------|------|
| `app/main.py` | 新建 | FastAPI 应用入口，组装所有路由 |
| `run.py` | 新建 | 启动脚本 |
| `tests/e2e/` | 新建 | 端到端测试 |

### 阶段 7: 清理

| 文件 | 操作 | 说明 |
|------|------|------|
| `FilePy.py` | 保留 | 标记为 deprecated，保留兼容性 |

## 核心设计原则

### 1. 依赖注入

```python
# app/api/deps.py
from functools import lru_cache
from app.core.config import settings

@lru_cache()
def get_settings():
    return settings

async def get_db():
    async with AsyncSession(database_engine) as session:
        yield session

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> TokenData:
    # 验证 JWT 并返回用户信息
    ...
```

### 2. 配置管理

```python
# app/core/config.py
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "FilePy"
    VERSION: str = "0.3.0"
    SECRET_KEY: str
    DATABASE_URL: str = "sqlite:///./filepy.db"

    # 测试模式
    TESTING: bool = False

    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()
```

### 3. 测试隔离

```python
# tests/conftest.py
import pytest
from app.core.database import init_database, drop_database
from app.core.config import settings

@pytest.fixture(scope="function")
async def test_db():
    # 使用内存数据库
    settings.TESTING = True
    settings.DATABASE_URL = "sqlite:///:memory:"

    await init_database()
    yield
    await drop_database()
```

## 测试策略

### 单元测试 (Unit Tests)
- 目标覆盖率: 95%+
- 测试范围: 工具函数、模型验证、配置解析
- 不依赖外部资源 (数据库、文件系统)

### 集成测试 (Integration Tests)
- 目标覆盖率: 90%+
- 测试范围: API 端点、服务层
- 使用测试数据库和临时文件系统

### E2E 测试 (End-to-End Tests)
- 测试范围: 完整用户流程
- 示例: 登录 → 上传文件 → 下载文件 → 删除文件

## 覆盖率目标

| 模块 | 目标覆盖率 | 优先级 |
|------|-----------|--------|
| core/ | 95%+ | 高 |
| models/ | 100% | 高 (Pydantic 自动验证) |
| services/ | 90%+ | 高 |
| api/ | 85%+ | 高 |
| utils/ | 95%+ | 中 |

## 实施顺序建议

1. **先建立测试基础设施** (阶段 1)
2. **自底向上重构** (核心模块 → 业务模块 → API)
3. **每个模块 TDD 开发** (先写测试，再实现)
4. **保持旧版本可运行** (渐进式迁移)

## 向后兼容

- 保留 `FilePy.py` 作为旧版入口
- `run.py` 作为新版入口
- 两个版本可以并存，直到完全迁移完成
