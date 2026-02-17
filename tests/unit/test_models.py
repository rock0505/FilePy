# -*- coding: utf-8 -*-
"""
用户模型单元测试
"""

import pytest
from app.models.user import (
    UserCreate,
    UserLogin,
    UserUpdate,
    UserResponse,
    PasswordChange
)


class TestUserCreate:
    """UserCreate 模型测试"""

    def test_valid_user_create(self):
        """测试有效的用户创建"""
        user = UserCreate(
            username="testuser",
            password="password123",
            email="test@example.com"
        )

        assert user.username == "testuser"
        assert user.password == "password123"
        assert user.email == "test@example.com"

    def test_user_create_without_email(self):
        """测试没有邮箱的用户创建"""
        user = UserCreate(
            username="testuser",
            password="password123"
        )

        assert user.username == "testuser"
        assert user.email is None

    def test_username_too_short(self):
        """测试用户名太短"""
        with pytest.raises(Exception):
            UserCreate(
                username="ab",  # 少于 3 个字符
                password="password123"
            )

    def test_password_too_short(self):
        """测试密码太短"""
        with pytest.raises(Exception):
            UserCreate(
                username="testuser",
                password="12345"  # 少于 6 个字符
            )

    def test_invalid_email(self):
        """测试无效邮箱"""
        with pytest.raises(Exception):
            UserCreate(
                username="testuser",
                password="password123",
                email="invalid-email"
            )


class TestUserLogin:
    """UserLogin 模型测试"""

    def test_valid_login(self):
        """测试有效的登录"""
        login = UserLogin(
            username="testuser",
            password="password123"
        )

        assert login.username == "testuser"
        assert login.password == "password123"


class TestUserUpdate:
    """UserUpdate 模型测试"""

    def test_update_email_only(self):
        """测试只更新邮箱"""
        update = UserUpdate(email="new@example.com")

        assert update.email == "new@example.com"
        assert update.password is None

    def test_update_password_only(self):
        """测试只更新密码"""
        update = UserUpdate(password="newpassword123")

        assert update.password == "newpassword123"
        assert update.email is None

    def test_update_both(self):
        """测试同时更新邮箱和密码"""
        update = UserUpdate(
            email="new@example.com",
            password="newpassword123"
        )

        assert update.email == "new@example.com"
        assert update.password == "newpassword123"


class TestPasswordChange:
    """PasswordChange 模型测试"""

    def test_valid_password_change(self):
        """测试有效的密码修改"""
        change = PasswordChange(
            old_password="oldpass123",
            new_password="newpass123"
        )

        assert change.old_password == "oldpass123"
        assert change.new_password == "newpass123"

    def test_new_password_too_short(self):
        """测试新密码太短"""
        with pytest.raises(Exception):
            PasswordChange(
                old_password="oldpass123",
                new_password="short"  # 少于 6 个字符
            )


class TestUserResponse:
    """UserResponse 模型测试"""

    def test_user_response_from_dict(self):
        """测试从字典创建用户响应"""
        data = {
            "id": 1,
            "username": "testuser",
            "email": "test@example.com",
            "is_admin": False,
            "force_password_change": False,
            "created_at": "2024-01-01T00:00:00"
        }

        user = UserResponse(**data)

        assert user.id == 1
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.is_admin is False
        assert user.force_password_change is False

    def test_user_response_admin(self):
        """测试管理员用户响应"""
        data = {
            "id": 1,
            "username": "admin",
            "email": "admin@example.com",
            "is_admin": True,
            "force_password_change": True,
            "created_at": None
        }

        user = UserResponse(**data)

        assert user.is_admin is True
        assert user.force_password_change is True
