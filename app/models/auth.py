# -*- coding: utf-8 -*-
"""
认证相关数据模型
"""

from typing import Optional
from pydantic import BaseModel


class TokenData(BaseModel):
    """Token 数据模型"""
    user_id: int
    username: str
    is_admin: bool = False
    exp: Optional[int] = None


class TokenResponse(BaseModel):
    """Token 响应模型"""
    access_token: str
    token_type: str = "bearer"
    force_password_change: bool = False
