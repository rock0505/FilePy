# -*- coding: utf-8 -*-
"""
FilePy 主应用入口

FastAPI 应用初始化和路由注册
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path

from app.core.config import settings


# 创建 FastAPI 应用
app = FastAPI(
    title=settings.PROJECT_NAME,
    description=settings.DESCRIPTION,
    version=settings.VERSION,
    docs_url="/docs" if not settings.TESTING else None,
    redoc_url="/redoc" if not settings.TESTING else None,
)


# =============================================================================
# CORS 中间件
# =============================================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# 路由注册
# =============================================================================

from app.api import auth, files

app.include_router(auth.router)
app.include_router(files.router)


# =============================================================================
# 静态文件服务
# =============================================================================

# 挂载存储目录
storage_path = Path(settings.STORAGE_DIR)
storage_path.mkdir(exist_ok=True)
app.mount("/storage", StaticFiles(directory=str(storage_path)), name="storage")


# =============================================================================
# 根路径和健康检查
# =============================================================================

@app.get("/")
async def root():
    """根路径 - 返回 Web 界面"""
    template_path = Path("templates/web_bootstrap.html")
    if template_path.exists():
        return FileResponse(str(template_path))
    return {
        "name": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "description": settings.DESCRIPTION
    }


@app.get("/api/info")
async def api_info():
    """API 信息端点"""
    return {
        "name": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "description": settings.DESCRIPTION
    }


@app.get("/health")
async def health_check():
    """健康检查端点"""
    return {"status": "healthy"}


# =============================================================================
# 前端页面
# =============================================================================

@app.get("/web")
async def web_interface():
    """返回 Web 界面"""
    template_path = Path("templates/web_bootstrap.html")
    if template_path.exists():
        return FileResponse(str(template_path))
    return {"message": "Web 界面未找到"}


# =============================================================================
# 启动事件
# =============================================================================

@app.on_event("startup")
async def startup_event():
    """应用启动时执行"""
    from app.core.database import get_database, init_database

    db = get_database()
    init_database(db)

    print(f"\n{'='*50}")
    print(f"{settings.PROJECT_NAME} v{settings.VERSION} 启动成功")
    print(f"{'='*50}\n")


@app.on_event("shutdown")
async def shutdown_event():
    """应用关闭时执行"""
    print(f"\n{settings.PROJECT_NAME} 正在关闭...")
