# -*- coding: utf-8 -*-
"""
设置 API 路由
"""

from fastapi import APIRouter, Depends

from app.core.database import Database
from app.api.deps import get_db, get_current_user
from app.models.auth import TokenData
from app.models.user_settings import UserSettingsUpdate, UserSettingsResponse, StorageInfo
from app.services.settings_service import SettingsService


router = APIRouter(prefix="/user", tags=["用户设置"])


@router.get("/settings", response_model=UserSettingsResponse)
async def get_settings(
    current_user: TokenData = Depends(get_current_user),
    db: Database = Depends(get_db)
):
    """
    获取用户设置

    Args:
        current_user: 当前用户
        db: 数据库实例

    Returns:
        UserSettingsResponse: 用户设置
    """
    service = SettingsService(db)
    settings = service.get_user_settings(current_user.user_id)
    return UserSettingsResponse(**settings)


@router.put("/settings")
async def update_settings(
    settings: UserSettingsUpdate,
    current_user: TokenData = Depends(get_current_user),
    db: Database = Depends(get_db)
):
    """
    更新用户设置

    Args:
        settings: 设置数据
        current_user: 当前用户
        db: 数据库实例

    Returns:
        dict: 操作结果
    """
    service = SettingsService(db)
    settings_dict = {k: v for k, v in settings.dict().items() if v is not None}
    service.update_user_settings(current_user.user_id, settings_dict)
    return {"message": "设置保存成功"}


@router.get("/storage", response_model=StorageInfo)
async def get_storage_info(
    db: Database = Depends(get_db)
):
    """
    获取存储信息

    Args:
        db: 数据库实例

    Returns:
        StorageInfo: 存储信息
    """
    service = SettingsService(db)
    info = service.get_storage_info()
    return StorageInfo(**info)
