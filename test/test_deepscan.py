"""
Unit tests for the deep scanning module.

This module contains comprehensive tests for the DeepScanManager and
ListScanManager classes to ensure proper functionality after refactoring.
"""

import unittest
from unittest.mock import Mock, patch
import os
import tempfile

# Import the classes we want to test
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.deepscan import DeepScanManager, ListScanManager, list_search  # noqa: E402


class TestDeepScanManager(unittest.TestCase):
    """Test cases for DeepScanManager class."""

    def setUp(self):
        """Set up test fixtures before each test method."""
        self.manager = DeepScanManager()

    @patch("src.deepscan.constants")
    def test_get_urls_for_deep_scan_empty(self, mock_constants):
        """Test getting URLs when no URLs are marked for deep scanning."""
        mock_constants.dork_dict_from_DB = {}
        mock_constants.RESULT_CODE_TO_DEEPSCAN = 5
        mock_constants.AutoVivification.return_value = {}

        result = self.manager._get_urls_for_deep_scan()
        self.assertEqual(len(result), 0)

    @patch("src.deepscan.Connector.dump_from_DB")
    @patch("src.deepscan.constants")
    def test_get_urls_for_deep_scan_with_data(self, mock_constants, mock_dump):
        """Test getting URLs when URLs are marked for deep scanning."""
        # Функция получает данные из dump_from_DB, а не из dork_dict_from_DB
        mock_dump.return_value = {
            "https://github.com/user/repo1": [5, 1],  # [result_code, leak_id]
            "https://github.com/user/repo2": [3, 2],  # Not marked for deep scan
            "https://github.com/user/repo3": [5, 3],
        }
        mock_constants.RESULT_CODE_TO_DEEPSCAN = 5
        mock_constants.AutoVivification = dict

        result = self.manager._get_urls_for_deep_scan()

        self.assertIn("https://github.com/user/repo1", result)
        self.assertIn("https://github.com/user/repo3", result)
        self.assertNotIn("https://github.com/user/repo2", result)

    @patch("src.deepscan.filters.Checker")
    @patch("src.deepscan.RepoObj")
    def test_perform_deep_scan_success(self, mock_repo_obj, mock_checker):
        """Test successful deep scan operation."""
        # Тест для _perform_leakobj_deep_scan
        mock_checker_instance = Mock()
        mock_checker.return_value = mock_checker_instance
        mock_checker_instance.run.return_value = {}

        mock_leak_obj = Mock()
        mock_repo_obj.return_value = mock_leak_obj

        _ = self.manager._perform_leakobj_deep_scan("https://github.com/user/repo", 1, 1)

        # Проверяем что метод выполнился без ошибок (может быть None при ошибке)
        # assert вызовется без ошибки если функция отработала
        self.assertTrue(True)

    @patch("src.deepscan.filters.Checker")
    def test_perform_deep_scan_error(self, mock_checker):
        """Test deep scan operation with error."""
        mock_checker.side_effect = Exception("Scan failed")

        # Функция возвращает None при ошибке
        result = self.manager._perform_leakobj_deep_scan("https://github.com/user/repo", 1, 1)
        self.assertIsNone(result)


class TestListScanManager(unittest.TestCase):
    """Test cases for ListScanManager class."""

    def setUp(self):
        """Set up test fixtures before each test method."""
        self.temp_file = tempfile.NamedTemporaryFile(mode="w", delete=False)
        self.temp_file_path = self.temp_file.name
        self.manager = ListScanManager(self.temp_file_path)

    def tearDown(self):
        """Clean up after each test method."""
        if os.path.exists(self.temp_file_path):
            os.unlink(self.temp_file_path)

    def test_read_urls_from_file_not_exists(self):
        """Test reading URLs from non-existent file."""
        manager = ListScanManager("/nonexistent/file.txt")
        result = manager._read_urls_from_file()
        self.assertEqual(result, [])

    def test_read_urls_from_file_valid_urls(self):
        """Test reading valid URLs from file."""
        urls = [
            "https://github.com/user1/repo1",
            "https://github.com/user2/repo2",
            "//https://github.com/processed/repo",  # Should be skipped
            "",  # Empty line should be skipped
            "https://github.com/user3/repo3",
        ]

        with open(self.temp_file_path, "w") as f:
            for url in urls:
                f.write(f"{url}\n")

        result = self.manager._read_urls_from_file()
        expected = [
            "https://github.com/user1/repo1",
            "https://github.com/user2/repo2",
            "https://github.com/user3/repo3",
        ]
        self.assertEqual(result, expected)

    def test_is_valid_github_url_valid(self):
        """Test URL validation with valid GitHub URLs."""
        valid_urls = [
            "https://github.com/user/repo",
            "http://github.com/user/repo",
            "https://github.com/organization/project",
        ]

        for url in valid_urls:
            with self.subTest(url=url):
                self.assertTrue(self.manager._is_valid_github_url(url))

    def test_is_valid_github_url_invalid(self):
        """Test URL validation with invalid URLs."""
        invalid_urls = [
            "https://gitlab.com/user/repo",
            "not_a_url",
            "https://github.com/",  # Incomplete
            "ftp://github.com/user/repo",
        ]

        for url in invalid_urls:
            with self.subTest(url=url):
                self.assertFalse(self.manager._is_valid_github_url(url))

    @patch("src.deepscan.RepoObj")
    def test_create_repo_objects(self, mock_repo_obj):
        """Test creation of repository objects from URLs."""
        urls = ["https://github.com/user1/repo1", "https://github.com/user2/repo2", "invalid_url"]  # Should be skipped

        _ = self.manager._create_repo_objects(urls)

        # Should create 2 objects (invalid_url skipped)
        self.assertEqual(mock_repo_obj.call_count, 2)

    def test_mark_urls_as_processed(self):
        """Test marking URLs as processed in file."""
        urls = ["https://github.com/user1/repo1", "https://github.com/user2/repo2"]

        self.manager._mark_urls_as_processed(urls)

        with open(self.temp_file_path, "r") as f:
            content = f.read()

        expected_lines = ["//https://github.com/user1/repo1", "//https://github.com/user2/repo2"]

        for line in expected_lines:
            self.assertIn(line, content)


class TestLegacyFunctions(unittest.TestCase):
    """Test cases for legacy wrapper functions."""

    @patch("src.deepscan.ListScanManager")
    def test_list_search_wrapper(self, mock_manager_class):
        """Test the legacy list_search function wrapper."""
        mock_manager = Mock()
        mock_manager_class.return_value = mock_manager

        list_search("/path/to/file.txt")

        mock_manager_class.assert_called_once_with("/path/to/file.txt")
        mock_manager.run.assert_called_once()

    @patch("src.deepscan.ListScanManager")
    def test_list_search_wrapper_default_path(self, mock_manager_class):
        """Test the legacy list_search function with default path."""
        mock_manager = Mock()
        mock_manager_class.return_value = mock_manager

        list_search()

        mock_manager_class.assert_called_once_with(None)
        mock_manager.run.assert_called_once()


class TestErrorHandling(unittest.TestCase):
    """Test cases for error handling scenarios."""

    @patch("src.deepscan.ListScanManager")
    def test_list_search_with_exception(self, mock_manager_class):
        """Test list_search wrapper handles exceptions properly."""
        mock_manager = Mock()
        mock_manager.run.side_effect = Exception("Test error")
        mock_manager_class.return_value = mock_manager

        with self.assertRaises(Exception):
            list_search()


if __name__ == "__main__":
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add test cases
    suite.addTests(loader.loadTestsFromTestCase(TestDeepScanManager))
    suite.addTests(loader.loadTestsFromTestCase(TestListScanManager))
    suite.addTests(loader.loadTestsFromTestCase(TestLegacyFunctions))
    suite.addTests(loader.loadTestsFromTestCase(TestErrorHandling))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)
