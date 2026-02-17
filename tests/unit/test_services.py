# -*- coding: utf-8 -*-
"""
认证服务单元测试
"""

import pytest
from app.services.auth_service import AuthService
from app.models.user import UserCreate
from app.core.database import Database


class TestAuthService:
    """AuthService 测试"""

    def test_create_user(self, test_database):
        """测试创建用户"""
        service = AuthService(test_database)

        user_data = UserCreate(
            username="testuser",
            password="password123",
            email="test@example.com"
        )

        user_id = service.create_user(user_data)

        assert user_id > 0

        # 验证用户已创建
        user = service.get_user_by_id(user_id)
        assert user is not None
        assert user['username'] == "testuser"

    def test_create_admin_user(self, test_database):
        """测试创建管理员用户"""
        service = AuthService(test_database)

        user_data = UserCreate(
            username="admin",
            password="admin123",
            email="admin@example.com"
        )

        user_id = service.create_user(user_data, is_admin=True)

        user = service.get_user_by_id(user_id)
        assert user['is_admin'] is True

    def test_authenticate_user_success(self, test_database):
        """测试成功的用户认证"""
        service = AuthService(test_database)

        # 先创建用户
        user_data = UserCreate(
            username="authuser",
            password="authpass123"
        )
        service.create_user(user_data)

        # 认证
        user = service.authenticate_user("authuser", "authpass123")

        assert user is not None
        assert user['username'] == "authuser"

    def test_authenticate_user_wrong_password(self, test_database):
        """测试错误密码认证"""
        service = AuthService(test_database)

        # 先创建用户
        user_data = UserCreate(
            username="authuser2",
            password="correctpass"
        )
        service.create_user(user_data)

        # 使用错误密码认证
        user = service.authenticate_user("authuser2", "wrongpass")

        assert user is None

    def test_authenticate_user_not_exists(self, test_database):
        """测试不存在的用户认证"""
        service = AuthService(test_database)

        user = service.authenticate_user("nonexistent", "password")

        assert user is None

    def test_login_success(self, test_database):
        """测试成功登录"""
        service = AuthService(test_database)

        # 先创建用户
        user_data = UserCreate(
            username="loginuser",
            password="loginpass123"
        )
        service.create_user(user_data)

        # 登录
        response = service.login("loginuser", "loginpass123")

        assert response is not None
        assert response.access_token is not None
        assert response.token_type == "bearer"

    def test_login_failure(self, test_database):
        """测试登录失败"""
        service = AuthService(test_database)

        response = service.login("nonexistent", "wrongpass")

        assert response is None

    def test_change_password_success(self, test_database):
        """测试成功修改密码"""
        service = AuthService(test_database)

        # 先创建用户
        user_data = UserCreate(
            username="pwduser",
            password="oldpass123"
        )
        user_id = service.create_user(user_data)

        # 修改密码
        result = service.change_password(user_id, "oldpass123", "newpass123")

        assert result is True

        # 验证新密码可以登录
        user = service.authenticate_user("pwduser", "newpass123")
        assert user is not None

    def test_change_password_wrong_old(self, test_database):
        """测试使用错误的旧密码修改"""
        service = AuthService(test_database)

        # 先创建用户
        user_data = UserCreate(
            username="pwduser2",
            password="originalpass"
        )
        user_id = service.create_user(user_data)

        # 使用错误的旧密码
        result = service.change_password(user_id, "wrongpass", "newpass123")

        assert result is False

    def test_get_user_by_username(self, test_database):
        """测试根据用户名获取用户"""
        service = AuthService(test_database)

        # 先创建用户
        user_data = UserCreate(
            username="nameuser",
            password="password123"
        )
        service.create_user(user_data)

        # 获取用户
        user = service.get_user_by_username("nameuser")

        assert user is not None
        assert user['username'] == "nameuser"

    def test_get_user_by_username_not_exists(self, test_database):
        """测试获取不存在的用户"""
        service = AuthService(test_database)

        user = service.get_user_by_username("nonexistent")

        assert user is None
