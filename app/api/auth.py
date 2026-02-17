# -*- coding: utf-8 -*-
"""
认证相关 API 路由
"""

from fastapi import APIRouter, Depends, HTTPException, status

from app.core.database import Database
from app.api.deps import get_db, get_current_user
from app.services.auth_service import AuthService
from app.models.user import UserCreate, UserLogin, UserResponse, PasswordChange
from app.models.auth import TokenResponse, TokenData


router = APIRouter(prefix="/auth", tags=["认证"])


@router.post("/login", response_model=TokenResponse)
async def login(
    user_data: UserLogin,
    db: Database = Depends(get_db)
):
    """
    用户登录

    Args:
        user_data: 用户登录数据 (JSON 格式)
        db: 数据库实例

    Returns:
        TokenResponse: 包含 access_token 的响应
    """
    service = AuthService(db)
    response = service.login(user_data.username, user_data.password)

    if response is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户名或密码错误",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return response


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    user_data: UserCreate,
    db: Database = Depends(get_db)
):
    """
    用户注册（仅管理员可用）

    Args:
        user_data: 用户创建数据
        db: 数据库实例

    Returns:
        UserResponse: 创建的用户信息
    """
    service = AuthService(db)

    try:
        user_id = service.create_user(user_data)
    except Exception as e:
        if "UNIQUE constraint" in str(e):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="用户名已存在"
            )
        raise

    user = service.get_user_by_id(user_id)

    return UserResponse(
        id=user['id'],
        username=user['username'],
        email=user.get('email'),
        is_admin=user['is_admin'],
        force_password_change=False,
        created_at=user.get('created_at')
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: TokenData = Depends(get_current_user),
    db: Database = Depends(get_db)
):
    """
    获取当前用户信息

    Args:
        current_user: 当前用户 Token 数据
        db: 数据库实例

    Returns:
        UserResponse: 用户信息
    """
    service = AuthService(db)
    user = service.get_user_by_id(current_user.user_id)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在"
        )

    return UserResponse(
        id=user['id'],
        username=user['username'],
        email=user.get('email'),
        is_admin=user['is_admin'],
        force_password_change=user.get('force_password_change', False),
        created_at=user.get('created_at')
    )


@router.post("/change-password")
async def change_password(
    password_data: PasswordChange,
    current_user: TokenData = Depends(get_current_user),
    db: Database = Depends(get_db)
):
    """
    修改当前用户密码

    Args:
        password_data: 密码修改数据
        current_user: 当前用户 Token 数据
        db: 数据库实例

    Returns:
        dict: 操作结果
    """
    service = AuthService(db)

    success = service.change_password(
        current_user.user_id,
        password_data.old_password,
        password_data.new_password
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="原密码错误"
        )

    return {"message": "密码修改成功"}
