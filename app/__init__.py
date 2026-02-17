# -*- coding: utf-8 -*-
"""
FilePy - 轻量级文件服务器

版本: v0.3.0
架构: 模块化 (TDD 驱动)
"""

__version__ = "0.3.0"
__author__ = "FilePy Team"
__description__ = "轻量级文件服务器，支持权限控制和安全加密"

from .core.config import settings
from .core.security import (
    verify_password,
    hash_password,
    create_access_token,
    decode_access_token
)

__all__ = [
    "settings",
    "verify_password",
    "hash_password",
    "create_access_token",
    "decode_access_token",
]
