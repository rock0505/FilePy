# -*- coding: utf-8 -*-
"""
FilePy 启动脚本

用于启动 FilePy 文件服务器
"""

import uvicorn
import os
import sys


def main():
    """主函数"""
    # 从环境变量读取配置
    host = os.getenv("FILEPY_HOST", "0.0.0.0")
    port = int(os.getenv("FILEPY_PORT", "1966"))

    # SSL 配置
    ssl_keyfile = os.getenv("FILEPY_SSL_KEYFILE")
    ssl_certfile = os.getenv("FILEPY_SSL_CERTFILE")

    print("\n" + "=" * 50)
    print("FilePy - 轻量级文件服务器")
    print("=" * 50)
    print(f"服务地址: http://{host}:{port}")
    print(f"Web 界面: http://{host}:{port}/web")
    print(f"API 文档: http://{host}:{port}/docs")
    print("=" * 50 + "\n")

    # 启动服务器
    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        reload=True,
        ssl_keyfile=ssl_keyfile,
        ssl_certfile=ssl_certfile,
    )


if __name__ == "__main__":
    main()
