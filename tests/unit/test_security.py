# -*- coding: utf-8 -*-
"""
安全模块单元测试
"""

import pytest
from datetime import timedelta
from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
    is_token_expired,
    pwd_context
)


class TestPasswordHashing:
    """密码哈希测试"""

    def test_hash_password(self):
        """测试密码哈希"""
        password = "test_password_123"
        hashed = hash_password(password)

        # 哈希后的密码应该与原始密码不同
        assert hashed != password
        # bcrypt 哈希应该以 $2b$ 开头
        assert hashed.startswith("$2b$")

    def test_verify_password_correct(self):
        """测试正确密码验证"""
        password = "correct_password"
        hashed = hash_password(password)

        assert verify_password(password, hashed) is True

    def test_verify_password_incorrect(self):
        """测试错误密码验证"""
        password = "correct_password"
        wrong_password = "wrong_password"
        hashed = hash_password(password)

        assert verify_password(wrong_password, hashed) is False

    def test_hash_different_passwords_different_hashes(self):
        """测试不同密码产生不同哈希"""
        password1 = "password_one"
        password2 = "password_two"

        hash1 = hash_password(password1)
        hash2 = hash_password(password2)

        assert hash1 != hash2

    def test_hash_same_password_different_hashes(self):
        """测试相同密码每次哈希结果不同（由于 salt）"""
        password = "same_password"

        hash1 = hash_password(password)
        hash2 = hash_password(password)

        # 由于 bcrypt 使用随机 salt，每次哈希结果应该不同
        assert hash1 != hash2
        # 但验证时都应该通过
        assert verify_password(password, hash1) is True
        assert verify_password(password, hash2) is True


class TestJWTTokens:
    """JWT Token 测试"""

    def test_create_token(self):
        """测试 Token 创建"""
        data = {
            "user_id": 1,
            "username": "testuser",
            "is_admin": False
        }

        token = create_access_token(data)

        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 0

    def test_decode_token(self):
        """测试 Token 解码"""
        data = {
            "user_id": 123,
            "username": "admin",
            "is_admin": True
        }

        token = create_access_token(data)
        decoded = decode_access_token(token)

        assert decoded is not None
        assert decoded["user_id"] == 123
        assert decoded["username"] == "admin"
        assert decoded["is_admin"] is True

    def test_decode_invalid_token(self):
        """测试解码无效 Token"""
        invalid_token = "invalid.token.here"

        decoded = decode_access_token(invalid_token)

        assert decoded is None

    def test_token_expiration(self):
        """测试 Token 过期时间"""
        data = {"user_id": 1}

        # 创建一个立即过期的 Token
        token = create_access_token(
            data,
            expires_delta=timedelta(seconds=-1)  # 已经过期
        )

        decoded = decode_access_token(token)
        # Token 过期后解码应该返回 None 或包含过期信息
        # 注意: JWT decode 默认会验证过期时间
        assert decoded is None

    def test_token_custom_expiration(self):
        """测试自定义过期时间"""
        data = {"user_id": 1}

        # 创建 2 小时后过期的 Token
        token = create_access_token(
            data,
            expires_delta=timedelta(hours=2)
        )

        decoded = decode_access_token(token)

        assert decoded is not None
        assert decoded["user_id"] == 1
        assert "exp" in decoded

    def test_is_token_expired_valid(self):
        """测试有效 Token"""
        data = {"user_id": 1}
        token = create_access_token(data)

        assert is_token_expired(token) is False

    def test_is_token_expired_invalid(self):
        """测试无效 Token"""
        assert is_token_expired("invalid_token") is True

    def test_is_token_expired_expired(self):
        """测试过期 Token"""
        data = {"user_id": 1}
        token = create_access_token(
            data,
            expires_delta=timedelta(seconds=-1)
        )

        assert is_token_expired(token) is True


class TestPwdContext:
    """密码上下文测试"""

    def test_pwd_context_exists(self):
        """测试密码上下文存在"""
        assert pwd_context is not None

    def test_pwd_context_schemes(self):
        """测试密码哈希方案"""
        # schemes() 是一个方法，需要调用它
        schemes = pwd_context.schemes()
        assert "bcrypt" in schemes
