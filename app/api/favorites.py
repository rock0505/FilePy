# -*- coding: utf-8 -*-
"""
收藏 API 路由
"""

from fastapi import APIRouter, Depends, HTTPException, status
from typing import List

from app.core.database import Database
from app.api.deps import get_db, get_current_user
from app.models.auth import TokenData
from app.models.favorite import FavoriteCreate, FavoriteResponse
from app.services.favorite_service import FavoriteService


router = APIRouter(prefix="/files/favorites", tags=["收藏"])


@router.get("", response_model=List[FavoriteResponse])
async def list_favorites(
    current_user: TokenData = Depends(get_current_user),
    db: Database = Depends(get_db)
):
    """
    获取收藏列表

    Args:
        current_user: 当前用户
        db: 数据库实例

    Returns:
        List[FavoriteResponse]: 收藏列表
    """
    service = FavoriteService(db)
    favorites = service.list_favorites(current_user.user_id)
    return [
        FavoriteResponse(
            id=f['id'],
            file_path=f['file_path'],
            file_name=f['file_name'],
            is_dir=f['is_dir'],
            file_size=f.get('file_size'),
            created_at=f['created_at']
        )
        for f in favorites
    ]


@router.post("")
async def add_favorite(
    data: FavoriteCreate,
    current_user: TokenData = Depends(get_current_user),
    db: Database = Depends(get_db)
):
    """
    添加收藏

    Args:
        data: 收藏数据
        current_user: 当前用户
        db: 数据库实例

    Returns:
        dict: 操作结果
    """
    service = FavoriteService(db)
    service.add_favorite(
        current_user.user_id,
        data.file_path,
        data.file_name,
        data.is_dir,
        data.file_size
    )
    return {"message": "收藏成功"}


@router.delete("/{file_path:path}")
async def remove_favorite(
    file_path: str,
    current_user: TokenData = Depends(get_current_user),
    db: Database = Depends(get_db)
):
    """
    取消收藏

    Args:
        file_path: 文件路径
        current_user: 当前用户
        db: 数据库实例

    Returns:
        dict: 操作结果
    """
    service = FavoriteService(db)
    service.remove_favorite(current_user.user_id, file_path)
    return {"message": "取消收藏成功"}


@router.get("/check/{file_path:path}")
async def check_favorite(
    file_path: str,
    current_user: TokenData = Depends(get_current_user),
    db: Database = Depends(get_db)
):
    """
    检查是否已收藏

    Args:
        file_path: 文件路径
        current_user: 当前用户
        db: 数据库实例

    Returns:
        dict: 收藏状态
    """
    service = FavoriteService(db)
    is_fav = service.is_favorite(current_user.user_id, file_path)
    return {"is_favorite": is_fav}
