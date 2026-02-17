# -*- coding: utf-8 -*-
"""
收藏相关数据模型
"""

from pydantic import BaseModel


class FavoriteCreate(BaseModel):
    """创建收藏请求"""
    file_path: str
    file_name: str
    is_dir: bool = False
    file_size: int = None


class FavoriteResponse(BaseModel):
    """收藏响应"""
    id: int
    file_path: str
    file_name: str
    is_dir: bool
    file_size: int = None
    created_at: str
