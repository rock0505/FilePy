# -*- coding: utf-8 -*-
"""
配置管理模块

使用 Pydantic Settings 管理应用配置
支持环境变量和 config.ini 文件
"""

import os
import configparser
from pathlib import Path
from typing import Optional, List
from functools import lru_cache
from pydantic import BaseModel, Field


class Settings(BaseModel):
    """应用配置"""

    # 应用基本信息
    PROJECT_NAME: str = "FilePy"
    VERSION: str = "0.3.0"
    DESCRIPTION: str = "轻量级文件服务器"

    # 服务器配置
    HOST: str = Field(default="0.0.0.0", alias="FILEPY_HOST")
    PORT: int = Field(default=1966, alias="FILEPY_PORT")

    # 安全配置
    SECRET_KEY: str = Field(..., alias="FILEPY_SECRET_KEY")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # 数据库配置
    DATABASE_URL: str = Field(default="sqlite:///./filepy.db", alias="FILEPY_DATABASE_URL")

    # 测试模式
    TESTING: bool = Field(default=False, alias="FILEPY_TESTING")

    # 上传配置
    MAX_UPLOAD_SIZE: int = 104857600  # 100MB

    # CORS 配置
    CORS_ORIGINS: List[str] = Field(
        default=["http://localhost:1966", "http://127.0.0.1:1966"],
        alias="FILEPY_CORS_ORIGINS"
    )

    # SSL/TLS 配置
    SSL_CERTFILE: Optional[str] = Field(default=None, alias="FILEPY_SSL_CERTFILE")
    SSL_KEYFILE: Optional[str] = Field(default=None, alias="FILEPY_SSL_KEYFILE")

    # 存储配置
    STORAGE_DIR: str = "storage"

    # 日志配置
    LOG_LEVEL: str = "INFO"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True
        extra = "ignore"

    @classmethod
    def from_config_file(cls, config_path: Optional[Path] = None) -> "Settings":
        """
        从 config.ini 文件加载配置

        Args:
            config_path: config.ini 文件路径，默认为项目根目录下的 config.ini

        Returns:
            Settings: 配置对象
        """
        if config_path is None:
            config_path = Path(__file__).parent.parent.parent / "config.ini"

        config = configparser.ConfigParser()

        if config_path.exists():
            config.read(config_path, encoding="utf-8")

            # 从 config.ini 读取配置
            config_dict = {}

            # 服务器配置
            if "server" in config:
                if "host" in config["server"]:
                    config_dict["FILEPY_HOST"] = config["server"]["host"]
                if "port" in config["server"]:
                    config_dict["FILEPY_PORT"] = int(config["server"]["port"])

            # 安全配置
            if "security" in config:
                if "secret_key" in config["security"]:
                    config_dict["FILEPY_SECRET_KEY"] = config["security"]["secret_key"]

            # 上传配置
            if "upload" in config:
                if "max_size" in config["upload"]:
                    config_dict["MAX_UPLOAD_SIZE"] = int(config["upload"]["max_size"])

            # CORS 配置
            if "cors" in config:
                if "allow_origins" in config["cors"]:
                    origins = config["cors"]["allow_origins"].split(",")
                    config_dict["FILEPY_CORS_ORIGINS"] = [
                        origin.strip() for origin in origins if origin.strip()
                    ]

            # 创建配置对象（环境变量优先级更高）
            return Settings(**config_dict)

        # 如果没有 config.ini，返回默认配置
        return cls()


def load_config() -> Settings:
    """
    加载配置

    优先级: 环境变量 > config.ini > 默认值

    Returns:
        Settings: 配置对象
    """
    try:
        # 首先尝试从 config.ini 加载
        return Settings.from_config_file()
    except Exception:
        # 如果失败，直接使用环境变量和默认值
        return Settings()


@lru_cache()
def get_settings() -> Settings:
    """
    获取配置单例

    使用 lru_cache 确保只创建一次

    Returns:
        Settings: 配置对象
    """
    return load_config()


# 全局配置实例
settings = get_settings()
