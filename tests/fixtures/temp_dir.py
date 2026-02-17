# -*- coding: utf-8 -*-
"""
临时目录和文件相关 fixtures
"""

import os
import shutil
import tempfile
from pathlib import Path
from typing import Generator
import pytest


@pytest.fixture(scope="function")
def temp_dir() -> Generator[Path, None, None]:
    """
    创建临时目录

    测试结束后自动清理

    用法:
        def test_something(temp_dir: Path):
            file_path = temp_dir / "test.txt"
            file_path.write_text("content")
            assert file_path.exists()
    """
    temp_path = Path(tempfile.mkdtemp(prefix="filepy_test_"))
    yield temp_path
    # 清理
    if temp_path.exists():
        shutil.rmtree(temp_path)


@pytest.fixture(scope="function")
def temp_file(temp_dir: Path) -> Path:
    """
    创建临时文件

    返回文件路径，文件已包含示例内容

    用法:
        def test_something(temp_file: Path):
            content = temp_file.read_text()
            assert "测试内容" in content
    """
    file_path = temp_dir / "test_file.txt"
    file_path.write_text("测试内容 Test Content 测试文件\n")
    return file_path


@pytest.fixture(scope="function")
def temp_storage_dir(temp_dir: Path) -> Path:
    """
    创建模拟存储目录

    用于文件上传/下载测试
    """
    storage_path = temp_dir / "storage"
    storage_path.mkdir(exist_ok=True)
    return storage_path


@pytest.fixture(scope="function")
def sample_files(temp_storage_dir: Path) -> dict:
    """
    创建示例文件集合

    返回包含各种类型文件的字典
    """
    files = {}

    # 文本文件
    txt_file = temp_storage_dir / "document.txt"
    txt_file.write_text("这是测试文档内容\nTest Document Content")
    files['txt'] = {
        'path': txt_file,
        'name': 'document.txt',
        'size': txt_file.stat().st_size,
        'mime_type': 'text/plain'
    }

    # 子目录
    sub_dir = temp_storage_dir / "subfolder"
    sub_dir.mkdir()
    files['dir'] = {
        'path': sub_dir,
        'name': 'subfolder',
        'is_dir': True
    }

    # JSON 文件
    json_file = temp_storage_dir / "config.json"
    json_file.write_text('{"setting": "value", "number": 123}')
    files['json'] = {
        'path': json_file,
        'name': 'config.json',
        'size': json_file.stat().st_size,
        'mime_type': 'application/json'
    }

    # 图片文件（模拟）
    img_file = temp_storage_dir / "image.png"
    img_file.write_bytes(b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR')
    files['image'] = {
        'path': img_file,
        'name': 'image.png',
        'size': img_file.stat().st_size,
        'mime_type': 'image/png'
    }

    return files


@pytest.fixture(scope="function")
def clean_env():
    """
    清理环境变量

    测试前保存当前环境变量，测试后恢复
    """
    original_env = os.environ.copy()
    yield
    # 恢复环境变量
    os.environ.clear()
    os.environ.update(original_env)
