# -*- coding: utf-8 -*-
"""
示例单元测试

验证测试框架是否正确配置
"""

import pytest
from pathlib import Path


class TestPathUtils:
    """路径工具测试"""

    def test_join_paths(self):
        """测试路径拼接"""
        path1 = Path("/home")
        path2 = Path("user", "documents")
        result = path1 / path2
        assert str(result) == "/home/user/documents" or str(result) == "\\home\\user\\documents"

    def test_file_extension(self):
        """测试文件扩展名获取"""
        file_path = Path("document.pdf")
        assert file_path.suffix == ".pdf"

    def test_file_name(self):
        """测试文件名获取"""
        file_path = Path("/home/user/document.pdf")
        assert file_path.name == "document.pdf"


class TestStringOperations:
    """字符串操作测试"""

    def test_string_concatenation(self):
        """测试字符串拼接"""
        result = "Hello" + " " + "World"
        assert result == "Hello World"

    def test_string_upper(self):
        """测试大写转换"""
        result = "hello".upper()
        assert result == "HELLO"

    def test_string_split(self):
        """测试字符串分割"""
        result = "a,b,c".split(",")
        assert result == ["a", "b", "c"]


class TestListOperations:
    """列表操作测试"""

    def test_list_append(self):
        """测试列表追加"""
        items = [1, 2, 3]
        items.append(4)
        assert items == [1, 2, 3, 4]

    def test_list_len(self):
        """测试列表长度"""
        items = [1, 2, 3]
        assert len(items) == 3

    def test_list_slice(self):
        """测试列表切片"""
        items = [1, 2, 3, 4, 5]
        assert items[1:3] == [2, 3]


@pytest.mark.parametrize("input,expected", [
    (1, 2),
    (2, 4),
    (3, 6),
    (10, 20),
])
def test_multiply_by_two(input, expected):
    """参数化测试示例"""
    assert input * 2 == expected


def test_temp_dir_fixture(temp_dir: Path):
    """测试临时目录 fixture"""
    # 创建测试文件
    test_file = temp_dir / "test.txt"
    test_file.write_text("content")

    # 验证文件存在
    assert test_file.exists()
    assert test_file.read_text() == "content"


def test_temp_file_fixture(temp_file: Path):
    """测试临时文件 fixture"""
    # 验证文件存在
    assert temp_file.exists()

    # 验证文件内容
    content = temp_file.read_text()
    assert "测试内容" in content
