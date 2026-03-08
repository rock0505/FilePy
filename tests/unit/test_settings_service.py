# -*- coding: utf-8 -*-
"""
设置服务单元测试
"""

import pytest
from pathlib import Path
from app.services.settings_service import SettingsService
from app.models.user import UserCreate


class TestSettingsService:
    """SettingsService 测试"""

    def test_get_user_settings_default(self, test_database, temp_dir):
        """测试获取默认用户设置"""
        service = SettingsService(test_database, storage_path=str(temp_dir))

        settings = service.get_user_settings(999)

        # 应该返回默认设置
        assert settings["theme"] == "light"
        assert settings["view_mode"] == "list"
        assert settings["items_per_page"] == 50
        assert settings["auto_refresh"] is True
        assert settings["confirm_delete"] is True

    def test_get_user_settings_existing(self, test_database, temp_dir):
        """测试获取已存在的用户设置"""
        service = SettingsService(test_database, storage_path=str(temp_dir))

        # 先更新设置
        service.update_user_settings(1, {"theme": "dark", "view_mode": "grid"})

        # 获取设置
        settings = service.get_user_settings(1)

        assert settings["theme"] == "dark"
        assert settings["view_mode"] == "grid"

    def test_update_user_settings(self, test_database, temp_dir):
        """测试更新用户设置"""
        service = SettingsService(test_database, storage_path=str(temp_dir))

        result = service.update_user_settings(
            1,
            {
                "theme": "dark",
                "view_mode": "grid",
                "items_per_page": 100,
                "auto_refresh": False,
                "confirm_delete": False,
            },
        )

        assert result is True

        # 验证更新
        settings = service.get_user_settings(1)
        assert settings["theme"] == "dark"
        assert settings["view_mode"] == "grid"
        assert settings["items_per_page"] == 100
        assert settings["auto_refresh"] is False
        assert settings["confirm_delete"] is False

    def test_update_user_settings_partial(self, test_database, temp_dir):
        """测试部分更新用户设置"""
        service = SettingsService(test_database, storage_path=str(temp_dir))

        # 先设置完整配置
        service.update_user_settings(
            1, {"theme": "dark", "view_mode": "grid", "items_per_page": 100}
        )

        # 只更新部分字段（注意：需要传入所有要保留的字段）
        service.update_user_settings(
            1, {"theme": "light", "view_mode": "grid", "items_per_page": 100}
        )

        # 验证设置已更新
        settings = service.get_user_settings(1)
        assert settings["theme"] == "light"
        assert settings["view_mode"] == "grid"
        assert settings["items_per_page"] == 100

    def test_update_user_settings_with_defaults(self, test_database, temp_dir):
        """测试更新时使用默认值"""
        service = SettingsService(test_database, storage_path=str(temp_dir))

        # 只提供一个值
        service.update_user_settings(1, {"theme": "dark"})

        settings = service.get_user_settings(1)

        # 其他字段应该使用默认值
        assert settings["theme"] == "dark"
        assert settings["view_mode"] == "list"  # 默认值
        assert settings["items_per_page"] == 50  # 默认值

    def test_get_storage_info(self, test_database, temp_dir):
        """测试获取存储信息"""
        service = SettingsService(test_database, storage_path=str(temp_dir))

        # 创建一些测试文件
        (temp_dir / "file1.txt").write_text("x" * 100)
        (temp_dir / "file2.txt").write_text("x" * 200)
        folder = temp_dir / "subfolder"
        folder.mkdir()

        info = service.get_storage_info()

        assert "used_space" in info
        assert "total_space" in info
        assert "file_count" in info
        assert "folder_count" in info

        # 验证文件数量（不计算根目录本身）
        assert info["file_count"] >= 2
        assert info["used_space"] >= 300

    def test_get_storage_info_empty(self, test_database, temp_dir):
        """测试空目录的存储信息"""
        service = SettingsService(test_database, storage_path=str(temp_dir))

        info = service.get_storage_info()

        assert info["file_count"] == 0
        assert info["used_space"] == 0

    def test_get_storage_info_nested_folders(self, test_database, temp_dir):
        """测试嵌套目录的存储信息"""
        service = SettingsService(test_database, storage_path=str(temp_dir))

        # 创建嵌套结构
        (temp_dir / "level1").mkdir()
        (temp_dir / "level1" / "level2").mkdir()
        (temp_dir / "level1" / "level2" / "file.txt").write_text("content")

        info = service.get_storage_info()

        assert info["file_count"] == 1
        # folder_count 会包括所有子目录
        assert info["folder_count"] >= 2

    def test_update_user_settings_multiple_times(self, test_database, temp_dir):
        """测试多次更新用户设置"""
        service = SettingsService(test_database, storage_path=str(temp_dir))

        # 第一次更新
        service.update_user_settings(1, {"theme": "dark"})
        settings = service.get_user_settings(1)
        assert settings["theme"] == "dark"

        # 第二次更新
        service.update_user_settings(1, {"theme": "light"})
        settings = service.get_user_settings(1)
        assert settings["theme"] == "light"

        # 第三次更新
        service.update_user_settings(1, {"items_per_page": 200})
        settings = service.get_user_settings(1)
        assert settings["theme"] == "light"  # 保持之前的值
        assert settings["items_per_page"] == 200

    def test_different_users_settings(self, test_database, temp_dir):
        """测试不同用户的设置隔离"""
        from app.services.auth_service import AuthService

        # 创建用户2
        auth_service = AuthService(test_database)
        auth_service.create_user(
            UserCreate(username="settings_user2", password="pass123"), is_admin=False
        )

        service = SettingsService(test_database, storage_path=str(temp_dir))

        # 用户1设置深色主题
        service.update_user_settings(1, {"theme": "dark"})

        # 用户2设置浅色主题
        service.update_user_settings(2, {"theme": "light"})

        # 验证设置是独立的
        settings_1 = service.get_user_settings(1)
        settings_2 = service.get_user_settings(2)

        assert settings_1["theme"] == "dark"
        assert settings_2["theme"] == "light"
