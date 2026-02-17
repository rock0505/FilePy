# -*- coding: utf-8 -*-
"""
用户设置相关数据模型
"""

from pydantic import BaseModel


class UserSettingsUpdate(BaseModel):
    """用户设置更新请求"""
    theme: str = None
    view_mode: str = None
    items_per_page: int = None
    auto_refresh: bool = None
    confirm_delete: bool = None


class UserSettingsResponse(BaseModel):
    """用户设置响应"""
    theme: str
    view_mode: str
    items_per_page: int
    auto_refresh: bool
    confirm_delete: bool


class StorageInfo(BaseModel):
    """存储信息响应"""
    used_space: int
    total_space: int
    file_count: int
    folder_count: int
