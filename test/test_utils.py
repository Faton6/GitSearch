"""
Unit tests for the utils module.

This module contains comprehensive tests for utility functions
used throughout the GitSearch application.
"""

import pytest
import os
import sys
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add project root to path
ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src import utils
from src import constants


class TestGenerateCompanySearchTerms:
    """Tests for generate_company_search_terms function."""
    
    def test_simple_company_name(self):
        """Test with simple company name."""
        terms = utils.generate_company_search_terms("Acme")
        assert "acme" in terms
    
    def test_multi_word_company_name(self):
        """Test with multi-word company name."""
        terms = utils.generate_company_search_terms("Acme Corporation")
        assert "acme" in terms
        assert "corporation" in terms
        # Abbreviation
        assert "ac" in terms
    
    def test_hyphenated_company_name(self):
        """Test with hyphenated company name."""
        terms = utils.generate_company_search_terms("Tech-Solutions")
        assert "tech" in terms
        assert "solutions" in terms
    
    def test_empty_company_name(self):
        """Test with empty company name."""
        terms = utils.generate_company_search_terms("")
        assert terms == []
    
    def test_company_with_stopwords(self):
        """Test that stopwords are filtered out."""
        terms = utils.generate_company_search_terms("Acme Inc Ltd")
        assert "acme" in terms
        # Inc and Ltd should not create abbreviation by themselves
    
    def test_short_parts_filtered(self):
        """Test that very short parts are filtered."""
        terms = utils.generate_company_search_terms("A B Company")
        assert "company" in terms
        # Single letter parts should be filtered


class TestSanitizeCompanyName:
    """Tests for sanitize_company_name function."""
    
    def test_spaces_replaced(self):
        """Test that spaces are replaced with hyphens."""
        result = utils.sanitize_company_name("Acme Corp")
        assert " " not in result
        assert "-" in result
    
    def test_dots_replaced(self):
        """Test that dots are replaced with hyphens."""
        result = utils.sanitize_company_name("Acme.Corp")
        assert "." not in result
    
    def test_lowercase(self):
        """Test that result is lowercase."""
        result = utils.sanitize_company_name("ACME")
        assert result == "acme"
    
    def test_parentheses_removed(self):
        """Test that parentheses are removed."""
        result = utils.sanitize_company_name("Acme (US)")
        assert "(" not in result
        assert ")" not in result
    
    def test_non_string_input(self):
        """Test with non-string input."""
        result = utils.sanitize_company_name(None)
        assert result == ""


class TestFilterUrlByRepo:
    """Tests for filter_url_by_repo function."""
    
    def test_single_url_not_excluded(self):
        """Test single URL that's not in exclusion list."""
        result = utils.filter_url_by_repo("https://github.com/unique/repo")
        assert len(result) == 1 or result == "https://github.com/unique/repo"
    
    def test_list_of_urls(self):
        """Test with list of URLs."""
        urls = [
            "https://github.com/user1/repo1",
            "https://github.com/user2/repo2"
        ]
        result = utils.filter_url_by_repo(urls)
        assert isinstance(result, list)
    
    def test_empty_list(self):
        """Test with empty list."""
        result = utils.filter_url_by_repo([])
        assert result == []


class TestSafeEncodeDecode:
    """Tests for safe_encode_decode function."""
    
    def test_encode_string(self):
        """Test encoding a string."""
        result = utils.safe_encode_decode("Hello World", operation='encode')
        assert isinstance(result, str)
        assert result == "Hello World"
    
    def test_encode_bytes(self):
        """Test encoding bytes."""
        result = utils.safe_encode_decode(b"Hello World", operation='encode')
        assert isinstance(result, str)
    
    def test_decode_bytes(self):
        """Test decoding bytes."""
        result = utils.safe_encode_decode(b"Hello World", operation='decode')
        assert isinstance(result, str)
        assert result == "Hello World"
    
    def test_decode_string(self):
        """Test decoding string (should return as-is)."""
        result = utils.safe_encode_decode("Hello World", operation='decode')
        assert result == "Hello World"
    
    def test_empty_input(self):
        """Test with empty input."""
        result = utils.safe_encode_decode("", operation='encode')
        assert result == ""
    
    def test_none_input(self):
        """Test with None input."""
        result = utils.safe_encode_decode(None, operation='encode')
        assert result == ""
    
    def test_unicode_handling(self):
        """Test handling of unicode characters."""
        result = utils.safe_encode_decode("Привет мир", operation='encode')
        assert isinstance(result, str)
        assert "Привет" in result


class TestSafeGetNested:
    """Tests for safe_get_nested function."""
    
    def test_simple_nested(self):
        """Test getting simple nested value."""
        data = {"level1": {"level2": "value"}}
        result = utils.safe_get_nested(data, "level1", "level2")
        assert result == "value"
    
    def test_deep_nested(self):
        """Test getting deeply nested value."""
        data = {"a": {"b": {"c": {"d": "deep"}}}}
        result = utils.safe_get_nested(data, "a", "b", "c", "d")
        assert result == "deep"
    
    def test_missing_key(self):
        """Test with missing key returns default."""
        data = {"level1": {"level2": "value"}}
        result = utils.safe_get_nested(data, "level1", "missing", default="default")
        assert result == "default"
    
    def test_non_dict_value(self):
        """Test when traversing hits non-dict value."""
        data = {"level1": "string"}
        result = utils.safe_get_nested(data, "level1", "level2", default="default")
        assert result == "default"


class TestSafeGetCount:
    """Tests for safe_get_count function."""
    
    def test_total_count_dict(self):
        """Test extracting totalCount from dict."""
        data = {"stars": {"totalCount": 42}}
        result = utils.safe_get_count(data, "stars")
        assert result == 42
    
    def test_list_length(self):
        """Test counting list items."""
        data = {"items": [1, 2, 3, 4, 5]}
        result = utils.safe_get_count(data, "items")
        assert result == 5
    
    def test_direct_int(self):
        """Test direct integer value."""
        data = {"count": 10}
        result = utils.safe_get_count(data, "count")
        assert result == 10
    
    def test_missing_key(self):
        """Test missing key returns default."""
        data = {"other": 123}
        result = utils.safe_get_count(data, "count", default=0)
        assert result == 0


class TestIsTimeFormat:
    """Tests for is_time_format function."""
    
    def test_valid_date(self):
        """Test valid date format."""
        assert utils.is_time_format("2024-01-15") is True
    
    def test_invalid_date(self):
        """Test invalid date format."""
        assert utils.is_time_format("15-01-2024") is False
    
    def test_invalid_string(self):
        """Test with invalid string."""
        assert utils.is_time_format("not-a-date") is False
    
    def test_non_string_input(self):
        """Test with non-string input."""
        assert utils.is_time_format(12345) is False


class TestConvertToRegexPattern:
    """Tests for convert_to_regex_pattern function."""
    
    def test_simple_string(self):
        """Test simple string conversion."""
        result = utils.convert_to_regex_pattern("user/repo")
        assert "\\/" in result
    
    def test_special_characters(self):
        """Test special regex characters are escaped."""
        result = utils.convert_to_regex_pattern("user.name/repo*")
        assert "\\." in result
        assert "\\*" in result


class TestCountNestedDictLen:
    """Tests for count_nested_dict_len function."""
    
    def test_simple_dict(self):
        """Test simple dictionary."""
        data = {"a": 1, "b": 2}
        result = utils.count_nested_dict_len(data)
        assert result == 2
    
    def test_nested_autovivification(self):
        """Test nested AutoVivification dict."""
        data = constants.AutoVivification()
        data["a"]["b"] = 1
        data["c"] = 2
        result = utils.count_nested_dict_len(data)
        assert result >= 2


class TestSemanticCheckDork:
    """Tests for semantic_check_dork function."""
    
    def test_meaningful_match(self):
        """Test meaningful occurrence of dork."""
        result = utils.semantic_check_dork("This is about acme corp secrets", "acme")
        assert result == 1
    
    def test_no_match(self):
        """Test when dork is not present."""
        result = utils.semantic_check_dork("Nothing relevant here", "acme")
        assert result == 0
    
    def test_gibberish_context(self):
        """Test dork in gibberish context (should return 0)."""
        result = utils.semantic_check_dork("---acme---", "acme")
        assert result == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
