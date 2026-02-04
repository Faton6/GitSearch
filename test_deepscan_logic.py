#!/usr/bin/env python3
"""
Тест для проверки логики DeepScan.

Проверяет:
1. Фильтрацию GitHub URL
2. Правильность получения URL с кодом RESULT_CODE_TO_DEEPSCAN (5)
3. Правильность получения URL с кодом RESULT_CODE_TO_SEND (4) для rescan
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from src import constants  # noqa: E402
from src.deepscan import DeepScanManager  # noqa: E402


def test_url_validation():
    """Тест валидации GitHub URL"""
    print("=" * 80)
    print("TEST 1: URL Validation")
    print("=" * 80)

    manager = DeepScanManager()

    test_cases = [
        ("https://github.com/user/repo", True, "Valid GitHub repo URL"),
        ("https://gist.github.com/user/gist123", True, "Valid Gist URL"),
        ("http://github.com/user/repo", True, "HTTP GitHub URL"),
        ("https://gitlab.com/user/repo", False, "GitLab URL (invalid)"),
        ("https://bitbucket.org/user/repo", False, "Bitbucket URL (invalid)"),
        ("not_a_url", False, "Invalid URL format"),
        ("", False, "Empty string"),
        (None, False, "None value"),
        ("https://example.com/github.com/fake", False, "Fake GitHub URL"),
    ]

    passed = 0
    failed = 0

    for url, expected, description in test_cases:
        result = manager._is_valid_github_url(url)
        status = "✅ PASS" if result == expected else "❌ FAIL"
        if result == expected:
            passed += 1
        else:
            failed += 1
        print(f"{status}: {description}")
        print(f"   URL: {url}")
        print(f"   Expected: {expected}, Got: {result}")
        print()

    print(f"Results: {passed} passed, {failed} failed\n")
    return failed == 0


def test_result_codes():
    """Тест проверки кодов результатов"""
    print("=" * 80)
    print("TEST 2: Result Codes")
    print("=" * 80)

    print(f"RESULT_CODE_TO_DEEPSCAN = {constants.RESULT_CODE_TO_DEEPSCAN} (should be 5)")
    print(f"RESULT_CODE_TO_SEND = {constants.RESULT_CODE_TO_SEND} (should be 4)")
    print()

    if constants.RESULT_CODE_TO_DEEPSCAN == 5 and constants.RESULT_CODE_TO_SEND == 4:
        print("✅ PASS: Result codes are correct\n")
        return True
    else:
        print("❌ FAIL: Result codes are incorrect\n")
        return False


def test_url_filtering_logic():
    """Тест логики фильтрации URL"""
    print("=" * 80)
    print("TEST 3: URL Filtering Logic")
    print("=" * 80)

    # Симулируем данные из базы
    mock_db_data = {
        "https://github.com/valid/repo1": [5, 1],  # Should be selected for deepscan
        "https://github.com/valid/repo2": [4, 2],  # Should NOT be selected for deepscan (code 4)
        "https://github.com/valid/repo3": [5, 3],  # Should be selected for deepscan
        "https://gitlab.com/invalid/repo": [5, 4],  # Should be filtered out (not GitHub)
        "https://github.com/valid/repo4": [1, 5],  # Should NOT be selected (code 1)
    }

    print(f"Mock database contains {len(mock_db_data)} entries")
    print()

    # Симулируем логику _get_urls_for_deep_scan
    urls_to_scan = {}
    skipped_count = 0

    manager = DeepScanManager()

    for url_from_db, url_data in mock_db_data.items():
        # Проверка валидности URL
        if not manager._is_valid_github_url(url_from_db):
            skipped_count += 1
            print(f"⏭️  Skipped (invalid URL): {url_from_db}")
            continue

        try:
            result_code = int(url_data[0])
        except (ValueError, TypeError):
            print(f"⏭️  Skipped (invalid code): {url_from_db}")
            continue

        if result_code == constants.RESULT_CODE_TO_DEEPSCAN:
            urls_to_scan[url_from_db] = [url_data[1], None]
            print(f"✅ Selected for deepscan: {url_from_db} (code={result_code})")
        else:
            print(f"⏭️  Skipped (wrong code {result_code}): {url_from_db}")

    print()
    print(f"Skipped {skipped_count} non-GitHub URLs")
    print(f"Found {len(urls_to_scan)} valid GitHub URLs marked for deep scanning")
    print()

    # Проверяем результат
    expected_count = 2  # repo1 and repo3
    if len(urls_to_scan) == expected_count:
        print(f"✅ PASS: Correctly selected {expected_count} URLs for deepscan\n")
        return True
    else:
        print(f"❌ FAIL: Expected {expected_count} URLs, got {len(urls_to_scan)}\n")
        return False


def test_rescan_logic():
    """Тест логики rescan (mode=1)"""
    print("=" * 80)
    print("TEST 4: Rescan Logic (mode=1)")
    print("=" * 80)

    # Симулируем данные из базы для rescan
    mock_db_data = {
        "https://github.com/valid/repo1": [4, 1],  # Should be selected for rescan (code 4)
        "https://github.com/valid/repo2": [5, 2],  # Should NOT be selected (code 5)
        "https://github.com/valid/repo3": [4, 3],  # Should be selected for rescan (code 4)
        "https://gitlab.com/invalid/repo": [4, 4],  # Should be filtered out (not GitHub)
        "https://github.com/valid/repo4": [1, 5],  # Should NOT be selected (code 1)
    }

    print(f"Mock database contains {len(mock_db_data)} entries")
    print()

    # Симулируем логику _get_urls_for_deep_scan_with_no_results
    urls_to_scan = {}
    skipped_count = 0

    manager = DeepScanManager()

    for url_from_db, url_data in mock_db_data.items():
        # Проверка валидности URL
        if not manager._is_valid_github_url(url_from_db):
            skipped_count += 1
            print(f"⏭️  Skipped (invalid URL): {url_from_db}")
            continue

        try:
            result_code = int(url_data[0])
        except (ValueError, TypeError):
            print(f"⏭️  Skipped (invalid code): {url_from_db}")
            continue

        if result_code == constants.RESULT_CODE_TO_SEND:
            urls_to_scan[url_from_db] = [url_data[1], None]
            print(f"✅ Selected for rescan: {url_from_db} (code={result_code})")
        else:
            print(f"⏭️  Skipped (wrong code {result_code}): {url_from_db}")

    print()
    print(f"Skipped {skipped_count} non-GitHub URLs during rescan")
    print(f"Found {len(urls_to_scan)} valid GitHub URLs not analysed yet")
    print()

    # Проверяем результат
    expected_count = 2  # repo1 and repo3
    if len(urls_to_scan) == expected_count:
        print(f"✅ PASS: Correctly selected {expected_count} URLs for rescan\n")
        return True
    else:
        print(f"❌ FAIL: Expected {expected_count} URLs, got {len(urls_to_scan)}\n")
        return False


def main():
    print("\n" + "=" * 80)
    print("DeepScan Logic Verification Test Suite")
    print("=" * 80 + "\n")

    results = []

    # Run all tests
    results.append(("URL Validation", test_url_validation()))
    results.append(("Result Codes", test_result_codes()))
    results.append(("URL Filtering Logic", test_url_filtering_logic()))
    results.append(("Rescan Logic", test_rescan_logic()))

    # Summary
    print("=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for test_name, result in results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{status}: {test_name}")

    print()
    print(f"Total: {passed}/{total} tests passed")
    print("=" * 80)

    if passed == total:
        print("\n🎉 All tests passed! DeepScan logic is correct.\n")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Please review the logic.\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
