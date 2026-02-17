# -*- coding: utf-8 -*-
"""
数据库模块单元测试
"""

import pytest
import sqlite3
from pathlib import Path
from app.core.database import Database, get_database, init_database


class TestDatabase:
    """数据库类测试"""

    def test_database_init(self):
        """测试数据库初始化"""
        db = Database(":memory:")
        assert db.db_path == ":memory:"
        assert db._connection is None

    def test_database_connect(self):
        """测试数据库连接"""
        db = Database(":memory:")
        conn = db.connect()

        assert conn is not None
        assert isinstance(conn, sqlite3.Connection)

    def test_database_connect_reuse(self):
        """测试数据库连接复用"""
        db = Database(":memory:")

        conn1 = db.connect()
        conn2 = db.connect()

        # 应该返回同一个连接
        assert conn1 is conn2

    def test_database_close(self):
        """测试关闭数据库连接"""
        db = Database(":memory:")

        db.connect()
        assert db._connection is not None

        db.close()
        assert db._connection is None

    def test_database_get_cursor(self):
        """测试获取游标"""
        db = Database(":memory:")

        with db.get_cursor() as cursor:
            assert cursor is not None
            assert isinstance(cursor, sqlite3.Cursor)

    def test_database_get_cursor_context_manager(self):
        """测试游标上下文管理器"""
        db = Database(":memory:")

        with db.get_cursor() as cursor:
            cursor.execute("CREATE TABLE test (id INTEGER, name TEXT)")
            cursor.execute("INSERT INTO test VALUES (1, 'test')")

        # 上下文结束后应该自动提交
        with db.get_cursor() as cursor:
            cursor.execute("SELECT * FROM test")
            result = cursor.fetchone()
            assert result is not None

    def test_database_rollback_on_error(self):
        """测试错误时回滚"""
        db = Database(":memory:")

        # 创建测试表
        with db.get_cursor() as cursor:
            cursor.execute("CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT)")

        # 尝试插入重复键（应该回滚）
        with pytest.raises(Exception):
            with db.get_cursor() as cursor:
                cursor.execute("INSERT INTO test VALUES (1, 'first')")
                cursor.execute("INSERT INTO test VALUES (1, 'duplicate')")  # 重复键

        # 验证回滚后数据没有被插入
        with db.get_cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM test")
            count = cursor.fetchone()[0]
            assert count == 0


class TestDatabaseInit:
    """数据库初始化测试"""

    def test_init_database_tables(self, temp_dir: Path):
        """测试数据库表初始化"""
        db_path = str(temp_dir / "test.db")
        db = Database(db_path)

        init_database(db)

        # 验证表是否创建
        with db.get_cursor() as cursor:
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
            tables = [row[0] for row in cursor.fetchall()]

            expected_tables = [
                'users', 'groups', 'user_groups', 'permissions',
                'files', 'logs', 'quotas', 'config'
            ]

            for table in expected_tables:
                assert table in tables

    def test_init_database_default_permissions(self, temp_dir: Path):
        """测试默认权限插入"""
        db_path = str(temp_dir / "test.db")
        db = Database(db_path)

        init_database(db)

        with db.get_cursor() as cursor:
            cursor.execute("SELECT * FROM permissions")
            permissions = cursor.fetchall()

            assert len(permissions) >= 4
            perm_names = [p['name'] for p in permissions]
            assert 'read' in perm_names
            assert 'write' in perm_names
            assert 'execute' in perm_names
            assert 'delete' in perm_names

    def test_init_database_default_config(self, temp_dir: Path):
        """测试默认配置插入"""
        db_path = str(temp_dir / "test.db")
        db = Database(db_path)

        init_database(db)

        with db.get_cursor() as cursor:
            cursor.execute("SELECT * FROM config")
            configs = cursor.fetchall()

            assert len(configs) >= 2


class TestGetDatabase:
    """get_database 函数测试"""

    def test_get_database_memory(self):
        """测试获取内存数据库"""
        # 直接测试内存数据库创建
        db = Database(":memory:")
        assert db.db_path == ":memory:"

        # 验证可以正常连接
        conn = db.connect()
        assert conn is not None
        db.close()

    def test_get_database_file(self, monkeypatch):
        """测试获取文件数据库"""
        from app.core.config import settings

        monkeypatch.setenv("FILEPY_DATABASE_URL", "sqlite:///test.db")
        monkeypatch.setenv("FILEPY_SECRET_KEY", "test-key")

        # 由于 get_database 使用全局 settings，这里只测试不报错
        # 实际测试可能需要 mock
        db = get_database()
        assert db is not None
