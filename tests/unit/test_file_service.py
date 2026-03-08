# -*- coding: utf-8 -*-
"""
文件服务单元测试
"""

import pytest
from pathlib import Path
from datetime import datetime
from app.services.file_service import FileService
from app.models.file import FileInfo, FileRename, FolderCreate, SearchQuery


class TestFileService:
    """FileService 测试"""

    def test_list_files_root(self, test_database, temp_dir):
        """测试列出根目录文件"""
        service = FileService(test_database, storage_path=str(temp_dir))

        # 创建测试文件
        (temp_dir / "test.txt").write_text("test content")
        (temp_dir / "subfolder").mkdir()

        files = service.list_files("/")

        assert len(files) == 2
        filenames = [f.name for f in files]
        assert "test.txt" in filenames
        assert "subfolder" in filenames

    def test_list_files_sorted(self, test_database, temp_dir):
        """测试文件排序（目录优先）"""
        service = FileService(test_database, storage_path=str(temp_dir))

        # 创建文件和目录
        (temp_dir / "z_file.txt").write_text("content")
        (temp_dir / "a_folder").mkdir()
        (temp_dir / "m_file.txt").write_text("content")

        files = service.list_files("/")

        # 目录应该排在前面
        assert files[0].is_dir is True
        assert files[0].name == "a_folder"

    def test_list_files_nonexistent_path(self, test_database, temp_dir):
        """测试列出不存在的目录"""
        service = FileService(test_database, storage_path=str(temp_dir))

        files = service.list_files("/nonexistent")

        assert files == []

    def test_create_folder(self, test_database, temp_dir):
        """测试创建目录"""
        service = FileService(test_database, storage_path=str(temp_dir))

        folder_data = FolderCreate(path="/", name="new_folder")

        result = service.create_folder(folder_data)

        assert result.is_dir is True
        assert result.name == "new_folder"
        assert (temp_dir / "new_folder").exists()

    def test_create_folder_nested(self, test_database, temp_dir):
        """测试创建嵌套目录"""
        service = FileService(test_database, storage_path=str(temp_dir))

        folder_data = FolderCreate(path="/parent", name="child")

        result = service.create_folder(folder_data)

        assert result.name == "child"
        assert (temp_dir / "parent" / "child").exists()

    def test_create_folder_already_exists(self, test_database, temp_dir):
        """测试创建已存在的目录"""
        service = FileService(test_database, storage_path=str(temp_dir))

        # 先创建目录
        (temp_dir / "existing").mkdir()

        folder_data = FolderCreate(path="/", name="existing")

        with pytest.raises(ValueError, match="目录已存在"):
            service.create_folder(folder_data)

    def test_rename_file(self, test_database, temp_dir):
        """测试重命名文件"""
        service = FileService(test_database, storage_path=str(temp_dir))

        # 创建测试文件
        (temp_dir / "old_name.txt").write_text("content")

        rename_data = FileRename(old_path="/old_name.txt", new_name="new_name.txt")

        result = service.rename_file(rename_data)

        assert result is True
        assert not (temp_dir / "old_name.txt").exists()
        assert (temp_dir / "new_name.txt").exists()

    def test_rename_file_nonexistent(self, test_database, temp_dir):
        """测试重命名不存在的文件"""
        service = FileService(test_database, storage_path=str(temp_dir))

        rename_data = FileRename(old_path="/nonexistent.txt", new_name="new.txt")

        result = service.rename_file(rename_data)

        assert result is False

    def test_rename_file_target_exists(self, test_database, temp_dir):
        """测试重命名到已存在的名称"""
        service = FileService(test_database, storage_path=str(temp_dir))

        (temp_dir / "file1.txt").write_text("content1")
        (temp_dir / "file2.txt").write_text("content2")

        rename_data = FileRename(old_path="/file1.txt", new_name="file2.txt")

        result = service.rename_file(rename_data)

        assert result is False

    def test_delete_file(self, test_database, temp_dir):
        """测试删除文件"""
        service = FileService(test_database, storage_path=str(temp_dir))

        (temp_dir / "to_delete.txt").write_text("content")

        result = service.delete_file("/to_delete.txt")

        assert result is True
        assert not (temp_dir / "to_delete.txt").exists()

    def test_delete_folder(self, test_database, temp_dir):
        """测试删除目录"""
        service = FileService(test_database, storage_path=str(temp_dir))

        folder = temp_dir / "folder_to_delete"
        folder.mkdir()
        (folder / "file.txt").write_text("content")

        result = service.delete_file("/folder_to_delete")

        assert result is True
        assert not folder.exists()

    def test_delete_file_nonexistent(self, test_database, temp_dir):
        """测试删除不存在的文件"""
        service = FileService(test_database, storage_path=str(temp_dir))

        result = service.delete_file("/nonexistent.txt")

        assert result is False

    def test_batch_delete(self, test_database, temp_dir):
        """测试批量删除"""
        service = FileService(test_database, storage_path=str(temp_dir))

        # 创建测试文件
        (temp_dir / "file1.txt").write_text("content1")
        (temp_dir / "file2.txt").write_text("content2")
        (temp_dir / "file3.txt").write_text("content3")

        result = service.batch_delete(["/file1.txt", "/file2.txt", "/nonexistent.txt"])

        assert result["success_count"] == 2
        assert result["failed_count"] == 1
        assert not (temp_dir / "file1.txt").exists()
        assert not (temp_dir / "file2.txt").exists()
        assert (temp_dir / "file3.txt").exists()

    def test_search_files_by_name(self, test_database, temp_dir):
        """测试按名称搜索文件"""
        service = FileService(test_database, storage_path=str(temp_dir))

        (temp_dir / "test_file.txt").write_text("content")
        (temp_dir / "other.txt").write_text("content")
        (temp_dir / "subfolder").mkdir()

        query = SearchQuery(path="/", name="test")

        results = service.search_files(query)

        assert len(results) == 1
        assert results[0].name == "test_file.txt"

    def test_search_files_by_size(self, test_database, temp_dir):
        """测试按大小搜索文件"""
        service = FileService(test_database, storage_path=str(temp_dir))

        (temp_dir / "small.txt").write_text("x")
        (temp_dir / "large.txt").write_text("x" * 1000)

        query = SearchQuery(path="/", min_size=100)

        results = service.search_files(query)

        assert len(results) == 1
        assert results[0].name == "large.txt"

    def test_search_files_recursive(self, test_database, temp_dir):
        """测试递归搜索"""
        service = FileService(test_database, storage_path=str(temp_dir))

        (temp_dir / "root.txt").write_text("content")
        subfolder = temp_dir / "sub"
        subfolder.mkdir()
        (subfolder / "nested.txt").write_text("content")

        query = SearchQuery(path="/", name=".txt")

        results = service.search_files(query)

        assert len(results) == 2

    def test_get_file_path(self, test_database, temp_dir):
        """测试获取文件完整路径"""
        service = FileService(test_database, storage_path=str(temp_dir))

        result = service.get_file_path("/test/file.txt")

        assert result == temp_dir / "test" / "file.txt"

    def test_log_action(self, test_database, temp_dir):
        """测试记录操作日志"""
        service = FileService(test_database, storage_path=str(temp_dir))

        service.log_action(
            user_id=1,
            action="file_upload",
            resource_type="file",
            resource_path="/test.txt",
            details="上传测试文件",
        )

        # 验证日志已记录
        with test_database.get_cursor() as cursor:
            cursor.execute(
                """SELECT * FROM logs WHERE user_id = 1 AND action = ?""",
                ("file_upload",),
            )
            log = cursor.fetchone()

        assert log is not None

    def test_get_recent_files(self, test_database, temp_dir):
        """测试获取最近文件"""
        service = FileService(test_database, storage_path=str(temp_dir))

        # 记录一些操作
        service.log_action(1, "file_view", "file", "/test1.txt")
        service.log_action(1, "file_upload", "file", "/test2.txt")
        service.log_action(1, "file_download", "file", "/test3.txt")

        recent = service.get_recent_files(user_id=1, limit=2)

        assert len(recent) == 2
        assert recent[0]["action"] in ("file_view", "file_upload", "file_download")

    def test_mime_type_detection(self, test_database, temp_dir):
        """测试 MIME 类型检测"""
        service = FileService(test_database, storage_path=str(temp_dir))

        # 测试目录
        assert service._get_mime_type(temp_dir) is None

        # 测试各种文件类型
        (temp_dir / "test.txt").write_text("text")
        (temp_dir / "test.json").write_text("{}")
        (temp_dir / "test.pdf").write_bytes(b"%PDF")

        assert service._get_mime_type(temp_dir / "test.txt") == "text/plain"
        assert service._get_mime_type(temp_dir / "test.json") == "application/json"
        assert service._get_mime_type(temp_dir / "test.pdf") == "application/pdf"
