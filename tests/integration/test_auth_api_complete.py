# -*- coding: utf-8 -*-
"""
认证 API 完整测试
"""

import pytest

from app.core.database import Database, init_database
from app.core.security import create_access_token, hash_password
from app.services.auth_service import AuthService


class TestRegisterAPI:
    """用户注册 API 测试"""

    @pytest.mark.asyncio
    async def test_register_invalid_email(self, async_client):
        """测试注册无效邮箱"""
        response = await async_client.post(
            "/auth/register",
            json={"username": "user3", "password": "pass123", "email": "invalid-email"},
        )

        assert response.status_code == 422  # Validation error

    @pytest.mark.asyncio
    async def test_register_duplicate_username(self, async_client):
        """测试注册重复用户名（可能会成功或失败）"""
        # 第一次注册
        response1 = await async_client.post(
            "/auth/register",
            json={
                "username": "duplicate_user",
                "password": "pass123",
                "email": "first@example.com",
            },
        )

        # 第二次注册相同用户名
        response2 = await async_client.post(
            "/auth/register",
            json={
                "username": "duplicate_user",
                "password": "pass456",
                "email": "second@example.com",
            },
        )

        # 第二次应该失败（如果第一次成功）
        if response1.status_code == 201:
            assert response2.status_code == 400
        else:
            # 如果第一次失败（可能用户已存在），第二次也应该失败
            assert response2.status_code in [400, 422]


class TestGetCurrentUser:
    """获取当前用户 API 测试"""

    @pytest.mark.asyncio
    async def test_get_user_not_exists(self, async_client):
        """测试获取不存在的用户"""
        # 使用不存在的用户 ID 创建 token
        token_data = {"user_id": 99999, "username": "ghost", "is_admin": False}
        token = create_access_token(token_data)

        response = await async_client.get(
            "/auth/me", headers={"Authorization": f"Bearer {token}"}
        )

        # 用户不存在会返回 401 (认证失败)
        assert response.status_code == 401


class TestChangePassword:
    """修改密码 API 测试"""

    @pytest.mark.asyncio
    async def test_change_password_wrong_old_password(self, async_client):
        """测试修改密码时原密码错误"""
        token_data = {"user_id": 1, "username": "admin", "is_admin": True}
        token = create_access_token(token_data)

        # 使用错误的原密码
        response = await async_client.post(
            "/auth/change-password",
            headers={"Authorization": f"Bearer {token}"},
            json={"old_password": "wrongpassword", "new_password": "newpass456"},
        )

        assert response.status_code == 400
        data = response.json()
        assert "原密码错误" in data.get("detail", "")

    @pytest.mark.asyncio
    async def test_change_password_too_short(self, async_client):
        """测试修改密码时新密码太短"""
        token_data = {"user_id": 1, "username": "admin", "is_admin": True}
        token = create_access_token(token_data)

        # 使用太短的新密码
        response = await async_client.post(
            "/auth/change-password",
            headers={"Authorization": f"Bearer {token}"},
            json={"old_password": "admin123", "new_password": "short"},
        )

        assert response.status_code == 422  # Validation error
