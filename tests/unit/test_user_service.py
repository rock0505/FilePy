# -*- coding: utf-8 -*-
"""
用户服务单元测试
"""

import pytest
from app.services.user_service import UserService
from app.models.user import UserCreate, UserUpdate
from app.core.database import Database, init_database


class TestUserService:
    """UserService 测试"""

    def test_create_user(self, test_database):
        """测试创建用户"""
        service = UserService(test_database)

        user_data = UserCreate(
            username="userservice_test",
            password="password123",
            email="userservice@example.com",
        )

        user_id = service.create_user(user_data)

        assert user_id > 0

        # 验证用户已创建
        user = service.get_user(user_id)
        assert user is not None
        assert user["username"] == "userservice_test"

    def test_get_user(self, test_database):
        """测试获取用户"""
        service = UserService(test_database)

        # 先创建用户
        user_data = UserCreate(username="getuser_test", password="password123")
        user_id = service.create_user(user_data)

        # 获取用户
        user = service.get_user(user_id)

        assert user is not None
        assert user["id"] == user_id
        assert user["username"] == "getuser_test"

    def test_get_user_not_exists(self, test_database):
        """测试获取不存在的用户"""
        service = UserService(test_database)

        user = service.get_user(99999)

        assert user is None

    def test_list_users(self, test_database):
        """测试列出所有用户"""
        service = UserService(test_database)

        # 创建几个测试用户
        for i in range(3):
            user_data = UserCreate(username=f"listuser_{i}", password="password123")
            service.create_user(user_data)

        # 获取用户列表
        users = service.list_users()

        assert len(users) >= 3
        # 应该包含默认 admin 用户
        usernames = [u["username"] for u in users]
        assert "admin" in usernames

    def test_update_user_email(self, test_database):
        """测试更新用户邮箱"""
        service = UserService(test_database)

        # 先创建用户
        user_data = UserCreate(
            username="updateuser_test", password="password123", email="old@example.com"
        )
        user_id = service.create_user(user_data)

        # 更新邮箱
        update_data = UserUpdate(email="new@example.com")
        result = service.update_user(user_id, update_data)

        assert result is True

        # 验证更新
        user = service.get_user(user_id)
        assert user["email"] == "new@example.com"

    def test_update_user_no_data(self, test_database):
        """测试不提供任何更新数据"""
        service = UserService(test_database)

        user_data = UserCreate(username="nodata_test", password="password123")
        user_id = service.create_user(user_data)

        # 空更新数据
        update_data = UserUpdate()
        result = service.update_user(user_id, update_data)

        assert result is False

    def test_delete_user(self, test_database):
        """测试删除用户"""
        service = UserService(test_database)

        # 先创建用户
        user_data = UserCreate(username="deleteuser_test", password="password123")
        user_id = service.create_user(user_data)

        # 删除用户
        result = service.delete_user(user_id)

        assert result is True

        # 验证已删除
        user = service.get_user(user_id)
        assert user is None

    def test_create_admin_user_via_service(self, test_database):
        """测试通过服务创建管理员用户"""
        service = UserService(test_database)

        user_data = UserCreate(
            username="service_admin",
            password="admin123",
            email="service_admin@example.com",
        )

        user_id = service.create_user(user_data, is_admin=True)

        user = service.get_user(user_id)
        assert user["is_admin"] is True
