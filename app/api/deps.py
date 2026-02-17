# -*- coding: utf-8 -*-
"""
API 依赖注入

提供 FastAPI 依赖注入函数
"""

from typing import Generator, Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.core.database import Database, get_database, init_database
from app.core.config import Settings, get_settings
from app.core.security import decode_access_token
from app.models.auth import TokenData


# 安全方案
security = HTTPBearer()


# =============================================================================
# 数据库依赖
# =============================================================================

def get_db() -> Generator[Database, None, None]:
    """
    获取数据库连接

    Returns:
        Database: 数据库实例
    """
    db = get_database()

    # 确保数据库已初始化
    try:
        init_database(db)
    except Exception:
        pass  # 可能已经初始化过

    yield db

    db.close()


# =============================================================================
# 配置依赖
# =============================================================================

async def get_settings_dep() -> Settings:
    """获取应用配置"""
    return get_settings()


# =============================================================================
# 认证依赖
# =============================================================================

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Database = Depends(get_db)
) -> TokenData:
    """
    获取当前登录用户

    Args:
        credentials: HTTP Bearer Token
        db: 数据库实例

    Returns:
        TokenData: 用户 Token 数据

    Raises:
        HTTPException: 认证失败
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="无法验证凭据",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # 解码 Token
    token = credentials.credentials
    payload = decode_access_token(token)

    if payload is None:
        raise credentials_exception

    # 获取用户信息
    user_id: int = payload.get("user_id")
    username: str = payload.get("username")
    is_admin: bool = payload.get("is_admin", False)

    if user_id is None or username is None:
        raise credentials_exception

    # 验证用户是否仍然存在
    with db.get_cursor() as cursor:
        cursor.execute(
            '''SELECT id FROM users WHERE id = ?''',
            (user_id,)
        )
        user = cursor.fetchone()

    if user is None:
        raise credentials_exception

    return TokenData(
        user_id=user_id,
        username=username,
        is_admin=is_admin,
        exp=payload.get("exp")
    )


async def get_current_admin(
    current_user: TokenData = Depends(get_current_user)
) -> TokenData:
    """
    获取当前管理员用户

    Args:
        current_user: 当前用户

    Returns:
        TokenData: 管理员用户数据

    Raises:
        HTTPException: 非管理员用户
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="需要管理员权限"
        )

    return current_user


# =============================================================================
# 可选认证依赖
# =============================================================================

async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(
        HTTPBearer(auto_error=False)
    ),
    db: Database = Depends(get_db)
) -> Optional[TokenData]:
    """
    获取当前用户（可选）

    如果没有提供 Token 或 Token 无效，返回 None

    Args:
        credentials: HTTP Bearer Token（可选）
        db: 数据库实例

    Returns:
        Optional[TokenData]: 用户数据，未认证返回 None
    """
    if credentials is None:
        return None

    token = credentials.credentials
    payload = decode_access_token(token)

    if payload is None:
        return None

    user_id: int = payload.get("user_id")
    username: str = payload.get("username")
    is_admin: bool = payload.get("is_admin", False)

    if user_id is None or username is None:
        return None

    with db.get_cursor() as cursor:
        cursor.execute(
            '''SELECT id FROM users WHERE id = ?''',
            (user_id,)
        )
        user = cursor.fetchone()

    if user is None:
        return None

    return TokenData(
        user_id=user_id,
        username=username,
        is_admin=is_admin,
        exp=payload.get("exp")
    )
