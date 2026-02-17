# -*- coding: utf-8 -*-
"""
简单的 API 集成测试
"""

import pytest


@pytest.mark.integration
def test_app_imports():
    """测试应用可以正常导入"""
    from app.main import app
    assert app is not None


@pytest.mark.integration
def test_config_loaded():
    """测试配置已加载"""
    from app.core.config import settings
    assert settings.PROJECT_NAME == "FilePy"
    assert settings.VERSION == "0.3.0"


@pytest.mark.integration
def test_database_module():
    """测试数据库模块"""
    from app.core.database import Database
    db = Database(":memory:")
    assert db is not None
    db.close()


@pytest.mark.integration
def test_security_module():
    """测试安全模块"""
    from app.core.security import hash_password, verify_password
    pwd = "test_password"
    hashed = hash_password(pwd)
    assert verify_password(pwd, hashed) is True


@pytest.mark.integration
def test_models_import():
    """测试模型可以正常导入"""
    from app.models.user import UserCreate, UserLogin
    from app.models.auth import TokenData
    from app.models.file import FileInfo

    # 测试创建模型实例
    user = UserCreate(username="test", password="password123")
    assert user.username == "test"

    login = UserLogin(username="test", password="pass")
    assert login.username == "test"

    token = TokenData(user_id=1, username="test")
    assert token.user_id == 1

    file_info = FileInfo(name="test.txt", path="/test.txt")
    assert file_info.name == "test.txt"


@pytest.mark.integration
def test_services_import():
    """测试服务可以正常导入"""
    from app.services.auth_service import AuthService
    from app.services.file_service import FileService
    from app.services.user_service import UserService

    # 验证类存在
    assert AuthService is not None
    assert FileService is not None
    assert UserService is not None
