# -*- coding: utf-8 -*-
"""
数据模型 (Pydantic Models)

定义所有 Pydantic 数据模型，用于请求/响应验证
"""

from .user import (
    UserCreate,
    UserLogin,
    UserResponse,
    UserUpdate,
    PasswordChange
)
from .auth import (
    TokenData,
    TokenResponse
)
from .file import (
    FileInfo,
    FileCreate,
    FileUpdate,
    FileRename,
    FolderCreate,
    BatchDelete,
    BatchRename,
    SearchQuery
)
from .quota import (
    QuotaSet,
    QuotaInfo,
    QuotaResponse
)

__all__ = [
    # 用户相关
    "UserCreate",
    "UserLogin",
    "UserResponse",
    "UserUpdate",
    "PasswordChange",
    # 认证相关
    "TokenData",
    "TokenResponse",
    # 文件相关
    "FileInfo",
    "FileCreate",
    "FileUpdate",
    "FileRename",
    "FolderCreate",
    "BatchDelete",
    "BatchRename",
    "SearchQuery",
    # 配额相关
    "QuotaSet",
    "QuotaInfo",
    "QuotaResponse",
]
