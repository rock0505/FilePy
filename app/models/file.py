# -*- coding: utf-8 -*-
"""
文件相关数据模型
"""

from typing import Optional, List, Dict
from pydantic import BaseModel, Field


class FileInfo(BaseModel):
    """文件信息模型"""
    name: str
    path: str
    size: Optional[int] = None
    mime_type: Optional[str] = None
    is_dir: bool = False
    modified: Optional[str] = None

    class Config:
        from_attributes = True


class FileCreate(BaseModel):
    """创建文件请求模型（内部使用）"""
    name: str
    path: str
    size: int
    mime_type: Optional[str] = None
    owner_id: int


class FileUpdate(BaseModel):
    """更新文件请求模型"""
    name: Optional[str] = None
    permissions: Optional[List[Dict]] = None


class FileRename(BaseModel):
    """重命名文件请求模型"""
    old_path: str = Field(..., description="原文件路径")
    new_name: str = Field(..., min_length=1, max_length=255, description="新文件名")


class FolderCreate(BaseModel):
    """创建目录请求模型"""
    name: str = Field(..., min_length=1, max_length=255, description="目录名称")
    path: str = Field(default="/", description="父目录路径")


class BatchDelete(BaseModel):
    """批量删除请求模型"""
    paths: List[str] = Field(..., min_items=1, description="要删除的文件路径列表")


class BatchRename(BaseModel):
    """批量重命名请求模型"""
    items: List[Dict[str, str]] = Field(
        ...,
        min_items=1,
        description="重命名项列表，格式: [{'old_path': '...', 'new_name': '...'}]"
    )


class SearchQuery(BaseModel):
    """搜索查询模型"""
    name: Optional[str] = Field(None, description="文件名（支持模糊搜索）")
    min_size: Optional[int] = Field(None, ge=0, description="最小文件大小（字节）")
    max_size: Optional[int] = Field(None, ge=0, description="最大文件大小（字节）")
    start_date: Optional[str] = Field(None, description="开始日期（ISO 格式）")
    end_date: Optional[str] = Field(None, description="结束日期（ISO 格式）")
    path: str = Field(default="/", description="搜索路径")
