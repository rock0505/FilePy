# -*- coding: utf-8 -*-
"""
API 路由模块

包含所有 FastAPI 路由和依赖注入
"""

from .deps import (
    get_db,
    get_current_user,
    get_current_admin,
    get_settings
)

__all__ = [
    "get_db",
    "get_current_user",
    "get_current_admin",
    "get_settings",
]
