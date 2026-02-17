# -*- coding: utf-8 -*-
"""
文件操作相关 API 路由
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.responses import FileResponse
from pathlib import Path

from app.core.database import Database
from app.api.deps import get_db, get_current_user
from app.models.auth import TokenData
from app.services.file_service import FileService
from app.models.file import (
    FileInfo,
    FileRename,
    FolderCreate,
    BatchDelete,
    SearchQuery
)


router = APIRouter(prefix="/files", tags=["文件"])


@router.get("", response_model=List[FileInfo])
async def list_files(
    path: str = Query("/", description="目录路径"),
    current_user: TokenData = Depends(get_current_user),
    db: Database = Depends(get_db)
):
    """
    列出目录下的文件

    Args:
        path: 目录路径
        current_user: 当前用户
        db: 数据库实例

    Returns:
        List[FileInfo]: 文件列表
    """
    service = FileService(db)
    # 记录目录查看操作
    service.log_action(current_user.user_id, 'file_view', 'folder', path)
    return service.list_files(path)


@router.post("/folder", response_model=FileInfo, status_code=status.HTTP_201_CREATED)
async def create_folder(
    folder_data: FolderCreate,
    current_user: TokenData = Depends(get_current_user),
    db: Database = Depends(get_db)
):
    """
    创建目录

    Args:
        folder_data: 目录创建数据
        current_user: 当前用户
        db: 数据库实例

    Returns:
        FileInfo: 创建的目录信息
    """
    service = FileService(db)

    try:
        return service.create_folder(folder_data)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post("/rename")
async def rename_file(
    rename_data: FileRename,
    current_user: TokenData = Depends(get_current_user),
    db: Database = Depends(get_db)
):
    """
    重命名文件或目录

    Args:
        rename_data: 重命名数据
        current_user: 当前用户
        db: 数据库实例

    Returns:
        dict: 操作结果
    """
    service = FileService(db)

    success = service.rename_file(rename_data)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="重命名失败"
        )

    return {"message": "重命名成功"}


@router.delete("/{file_path:path}")
async def delete_file(
    file_path: str,
    current_user: TokenData = Depends(get_current_user),
    db: Database = Depends(get_db)
):
    """
    删除文件或目录

    Args:
        file_path: 文件路径
        current_user: 当前用户
        db: 数据库实例

    Returns:
        dict: 操作结果
    """
    service = FileService(db)

    success = service.delete_file(file_path)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="文件不存在"
        )

    return {"message": "删除成功"}


@router.post("/batch-delete")
async def batch_delete_files(
    delete_data: BatchDelete,
    current_user: TokenData = Depends(get_current_user),
    db: Database = Depends(get_db)
):
    """
    批量删除文件

    Args:
        delete_data: 批量删除数据
        current_user: 当前用户
        db: 数据库实例

    Returns:
        dict: 操作结果统计
    """
    service = FileService(db)
    return service.batch_delete(delete_data.paths)


@router.get("/download/{file_path:path}")
async def download_file(
    file_path: str,
    current_user: TokenData = Depends(get_current_user),
    db: Database = Depends(get_db)
):
    """
    下载文件

    Args:
        file_path: 文件路径
        current_user: 当前用户
        db: 数据库实例

    Returns:
        FileResponse: 文件响应
    """
    service = FileService(db)
    full_path = service.get_file_path(file_path)

    if not full_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="文件不存在"
        )

    if full_path.is_dir():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="无法下载目录"
        )

    return FileResponse(
        path=str(full_path),
        filename=full_path.name,
        media_type='application/octet-stream'
    )


@router.post("/search", response_model=List[FileInfo])
async def search_files(
    query: SearchQuery,
    current_user: TokenData = Depends(get_current_user),
    db: Database = Depends(get_db)
):
    """
    搜索文件

    Args:
        query: 搜索查询
        current_user: 当前用户
        db: 数据库实例

    Returns:
        List[FileInfo]: 搜索结果
    """
    service = FileService(db)
    return service.search_files(query)


@router.get("/recent")
async def get_recent_files(
    limit: int = Query(20, description="返回数量限制", ge=1, le=100),
    current_user: TokenData = Depends(get_current_user),
    db: Database = Depends(get_db)
):
    """
    获取最近访问的文件

    Args:
        limit: 返回数量限制
        current_user: 当前用户
        db: 数据库实例

    Returns:
        List[dict]: 最近文件列表
    """
    service = FileService(db)
    return service.get_recent_files(current_user.user_id, limit)
