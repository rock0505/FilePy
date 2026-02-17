# -*- coding: utf-8 -*-
"""
配额相关数据模型
"""

from typing import Optional
from pydantic import BaseModel, Field


class QuotaSet(BaseModel):
    """设置配额请求模型"""
    user_id: int = Field(..., description="用户 ID")
    quota_limit: int = Field(..., ge=0, description="配额限制（字节），0 表示无限制")
    warning_threshold: int = Field(default=80, ge=0, le=100, description="预警阈值（百分比）")


class QuotaInfo(BaseModel):
    """配额信息模型"""
    quota_limit: int
    quota_used: int
    warning_threshold: int
    usage_percent: float
    unlimited: bool = False


class QuotaResponse(BaseModel):
    """配额响应模型"""
    quota_limit: int
    quota_used: int
    warning_threshold: int
    usage_percent: float
    unlimited: bool = False
    warning: Optional[dict] = None
    disk_usage: Optional[dict] = None
