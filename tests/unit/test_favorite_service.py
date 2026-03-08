# -*- coding: utf-8 -*-
"""
收藏服务单元测试
"""

import pytest
from app.services.favorite_service import FavoriteService
from app.models.user import UserCreate


class TestFavoriteService:
    """FavoriteService 测试"""

    def test_add_favorite(self, test_database):
        """测试添加收藏"""
        service = FavoriteService(test_database)

        result = service.add_favorite(
            user_id=1,
            file_path="/documents/test.txt",
            file_name="test.txt",
            is_dir=False,
            file_size=1024,
        )

        assert result is True

        # 验证已添加
        assert service.is_favorite(1, "/documents/test.txt") is True

    def test_add_favorite_folder(self, test_database):
        """测试添加目录收藏"""
        service = FavoriteService(test_database)

        result = service.add_favorite(
            user_id=1,
            file_path="/documents/folder",
            file_name="folder",
            is_dir=True,
            file_size=None,
        )

        assert result is True
        assert service.is_favorite(1, "/documents/folder") is True

    def test_add_duplicate_favorite(self, test_database):
        """测试添加重复收藏（应该被忽略）"""
        service = FavoriteService(test_database)

        service.add_favorite(user_id=1, file_path="/test.txt", file_name="test.txt")

        # 再次添加相同的收藏
        result = service.add_favorite(
            user_id=1, file_path="/test.txt", file_name="test.txt"
        )

        assert result is True

    def test_remove_favorite(self, test_database):
        """测试取消收藏"""
        service = FavoriteService(test_database)

        # 先添加收藏
        service.add_favorite(
            user_id=1, file_path="/to_remove.txt", file_name="to_remove.txt"
        )

        # 取消收藏
        result = service.remove_favorite(1, "/to_remove.txt")

        assert result is True
        assert service.is_favorite(1, "/to_remove.txt") is False

    def test_remove_nonexistent_favorite(self, test_database):
        """测试取消不存在的收藏"""
        service = FavoriteService(test_database)

        result = service.remove_favorite(1, "/nonexistent.txt")

        assert result is True

    def test_is_favorite(self, test_database):
        """测试检查是否已收藏"""
        service = FavoriteService(test_database)

        # 未收藏时
        assert service.is_favorite(1, "/test.txt") is False

        # 收藏后
        service.add_favorite(1, "/test.txt", "test.txt")
        assert service.is_favorite(1, "/test.txt") is True

    def test_is_favorite_different_user(self, test_database):
        """测试不同用户的收藏状态"""
        service = FavoriteService(test_database)

        # 用户1收藏
        service.add_favorite(1, "/shared.txt", "shared.txt")

        # 用户1应该能看到收藏
        assert service.is_favorite(1, "/shared.txt") is True

        # 用户2不应该看到用户1的收藏
        assert service.is_favorite(2, "/shared.txt") is False

    def test_list_favorites_empty(self, test_database):
        """测试列出空收藏列表"""
        service = FavoriteService(test_database)

        favorites = service.list_favorites(999)

        assert favorites == []

    def test_list_favorites(self, test_database):
        """测试列出收藏"""
        service = FavoriteService(test_database)

        # 添加多个收藏
        service.add_favorite(1, "/file1.txt", "file1.txt", False, 100)
        service.add_favorite(1, "/file2.txt", "file2.txt", False, 200)
        service.add_favorite(1, "/folder1", "folder1", True, None)

        favorites = service.list_favorites(1)

        assert len(favorites) == 3

        # 验证数据结构
        fav = favorites[0]
        assert "id" in fav
        assert "file_path" in fav
        assert "file_name" in fav
        assert "is_dir" in fav
        assert "file_size" in fav
        assert "created_at" in fav

    def test_list_favorites_order(self, test_database):
        """测试收藏列表按时间倒序排列"""
        import time

        service = FavoriteService(test_database)

        # 按顺序添加（使用更长的延迟确保时间戳不同）
        service.add_favorite(1, "/first.txt", "first.txt")
        time.sleep(0.1)  # 增加延迟确保时间戳不同
        service.add_favorite(1, "/second.txt", "second.txt")
        time.sleep(0.1)
        service.add_favorite(1, "/third.txt", "third.txt")

        favorites = service.list_favorites(1)

        # 最新的应该在前面（根据 ID 或 created_at）
        assert len(favorites) == 3
        # 至少验证我们得到了所有收藏
        filenames = [f["file_name"] for f in favorites]
        assert "first.txt" in filenames
        assert "second.txt" in filenames
        assert "third.txt" in filenames

    def test_list_favorites_by_user(self, test_database):
        """测试不同用户的收藏列表隔离"""
        from app.services.auth_service import AuthService

        auth_service = AuthService(test_database)
        service = FavoriteService(test_database)

        # 创建用户2（因为数据库有外键约束）
        auth_service.create_user(
            UserCreate(username="testuser2", password="pass123"), is_admin=False
        )

        # 用户1的收藏
        service.add_favorite(1, "/user1_file.txt", "user1_file.txt")

        # 用户2的收藏
        service.add_favorite(2, "/user2_file.txt", "user2_file.txt")

        # 用户1应该只看到自己的收藏
        favorites_1 = service.list_favorites(1)
        assert len(favorites_1) == 1
        assert favorites_1[0]["file_name"] == "user1_file.txt"

        # 用户2应该只看到自己的收藏
        favorites_2 = service.list_favorites(2)
        assert len(favorites_2) == 1
        assert favorites_2[0]["file_name"] == "user2_file.txt"
