import re
import math
import functools
import string
from collections import Counter
from typing import Dict, FrozenSet, Tuple, List, Optional, Set
from src.logger import logger
from src import constants
from src import Connector
from src import utils

# ?????????????????????? ?????????????????? ???? constants.py ?????? ????????????????????????
from src.constants import (
    SECRET_CLASSIFICATION,
    KNOWN_PLACEHOLDER_PATTERNS,
    FALSE_POSITIVE_PATH_PATTERNS,
    FRAMEWORK_CONFIG_PATTERNS,
    MIN_ENTROPY_THRESHOLDS,
    BINARY_FILE_EXTENSIONS,
    DATA_FILE_EXTENSIONS,
    KNOWN_EXAMPLE_SECRETS,
    TUTORIAL_REPO_PATTERNS,
    TEMPLATE_CONFIG_PATTERNS,
    LOCAL_HOST_PATTERNS,
    MOCK_DATA_PATH_PATTERNS,
    REPO_SIZE_TINY_KB,
    REPO_SIZE_SMALL_KB,
    REPO_AGE_NEW_DAYS,
    REPO_AGE_ABANDONED_DAYS,
    REPO_MAX_STARS_FOR_PERSONAL,
    REPO_STARS_HIGH,
    REPO_STARS_VERY_HIGH,
    REPO_FORKS_HIGH,
    REPO_CONTRIBUTORS_HIGH,
)

# ???????????????? base64/hex ?????????? (?????? ?????????????????????? ?????????????????? ????????????)
BASE64_PATTERN = re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$')
HEX_PATTERN = re.compile(r'^[A-Fa-f0-9]{32,}$')
UUID_PATTERN = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)

# ?????????????????????? ?????????? ???????????????????????? ?????????????????? ?????????? ?????? ????????????
MIN_KEYWORD_CONTEXT_LENGTH = 3

# ???????????????????????? ?????????????????? ???????? ???????????? ???????????????? (?????? ?????????????????????? ?????????????????? ??????????)
MAX_SINGLE_CASE_RATIO = 0.95


class LeakAnalyzer: 
    """
    Class to analyze the profitability of a leak based on organization relevance and sensitive data presence.
    
    ??????????????????????:
    - ?????????????????????? ???????????????????????????????? ???????????????????? ??????????????????
    - ???????????????????????????? ?????????????????????? ???????????????? ?????????????????????????? ????????????????
    - ?????????????? ?????????????????????????? ?????????????????? ?????????????????????????? ??????????????
    
    ?????????????????? ?????? ???????????????? false positive:
    - ?????????????????????? ???????????? ????????????????
    - ?????????????????????? ???????????????? placeholder ????????????????
    - ???????????? ?????????????????? ???????????? (test/example ????????????????????)
    - ???????????????? ?????????????????????????? ??????????????????
    - ?????????????????? ?????????????? ???????????????? ???? ????????
    """
    
    # ?????? ?????? ???????????????????????????????? regex ?????????????????? ???? ???????????? ????????????
    _compiled_patterns_cache: Dict[str, re.Pattern] = {}
    _domain_patterns_cache: Dict[FrozenSet[str], Dict] = {}
    
    def __init__(self, leak_obj: any, bad_file_ext: bool = False):
        self.leak_obj = leak_obj
        self.bad_file_ext = bad_file_ext
        self.company_name = Connector.get_company_name(leak_obj.company_id)
        self.company_tokens = utils.generate_company_search_terms(self.company_name)
        
        # Context keywords that increase/decrease secret value
        self.context_keywords = {
            "critical": {
                "prod": 0.3, "production": 0.3, "live": 0.3,
                "database": 0.25, "db": 0.25, "mysql": 0.2, "postgres": 0.2,
                "admin": 0.2, "root": 0.2, "master": 0.2,
                "secret": 0.15, "private": 0.15, "confidential": 0.15,
                "aws": 0.25, "azure": 0.2, "gcp": 0.2, "cloud": 0.15,
                "payment": 0.3, "stripe": 0.25, "paypal": 0.25,
            },
            "negative": {
                "test": -0.3, "testing": -0.3, "unittest": -0.35,
                "dev": -0.2, "development": -0.2, "local": -0.15,
                "demo": -0.3, "example": -0.35, "sample": -0.35,
                "dummy": -0.4, "fake": -0.4, "mock": -0.35, "stub": -0.3,
                "template": -0.3, "boilerplate": -0.3, "skeleton": -0.25,
                "tutorial": -0.35, "guide": -0.3, "readme": -0.25,
                "sandbox": -0.3, "playground": -0.3,
                "fixture": -0.35, "spec": -0.3,
            }
        }
        
        # Corporate domain patterns will be generated dynamically (lazy initialization)
        self._corporate_domain_patterns = None
        
    @staticmethod
    def calculate_entropy(text: str) -> float:
        """
        Calculate Shannon entropy of a string.
        Higher entropy indicates more randomness (likely real secret).
        
        Args:
            text: String to analyze
            
        Returns:
            float: Entropy value (0.0 - ~4.7 for ASCII)
        """
        if not text:
            return 0.0
        
        # Count character frequencies
        freq = Counter(text)
        length = len(text)
        
        # Calculate entropy
        entropy = 0.0
        for count in freq.values():
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        
        return entropy
    
    @staticmethod
    def has_repetitive_pattern(text: str, min_length: int = 3) -> bool:
        """
        Check if string contains repetitive patterns that indicate fake data.
        
        Args:
            text: String to check
            min_length: Minimum pattern length to detect
            
        Returns:
            bool: True if repetitive pattern detected
        """
        if not text or len(text) < min_length * 2:
            return False
        
        text_lower = text.lower()
        
        # Check for simple repetitions (aaa, 111, etc.)
        for i in range(len(text_lower) - min_length):
            char = text_lower[i]
            if text_lower[i:i+min_length] == char * min_length:
                return True
        
        # Check for repeating sequences (abcabc, 123123, etc.)
        for pattern_len in range(min_length, len(text_lower) // 2 + 1):
            pattern = text_lower[:pattern_len]
            if text_lower == pattern * (len(text_lower) // pattern_len) + pattern[:len(text_lower) % pattern_len]:
                return True
        
        # Check for sequential patterns (abc, 123, xyz)
        sequential_patterns = [
            string.ascii_lowercase,
            string.ascii_uppercase,
            string.digits,
            string.digits[::-1],  # reverse digits
        ]
        
        for seq in sequential_patterns:
            for i in range(len(seq) - min_length + 1):
                if seq[i:i+min_length] in text_lower:
                    # Check if a significant portion is sequential
                    if len(seq[i:i+min_length]) >= len(text) // 2:
                        return True
        
        return False
    
    @staticmethod
    def is_known_placeholder(text: str) -> bool:
        """
        Check if the text is a known placeholder value.
        
        Args:
            text: String to check
            
        Returns:
            bool: True if text matches known placeholder
        """
        if not text:
            return False
        
        text_lower = text.lower().strip()
        
        # Direct match with known placeholders
        if text_lower in KNOWN_PLACEHOLDER_PATTERNS:
            return True
        
        # Check for patterns that start with known placeholder prefixes
        placeholder_prefixes = ["your_", "your-", "my_", "my-", "test_", "test-", 
                               "example_", "example-", "sample_", "sample-",
                               "dummy_", "dummy-", "fake_", "fake-"]
        for prefix in placeholder_prefixes:
            if text_lower.startswith(prefix):
                return True
        
        # Check for patterns that end with known suffixes
        placeholder_suffixes = ["_here", "-here", "_example", "-example", 
                               "_placeholder", "-placeholder", "_test", "-test"]
        for suffix in placeholder_suffixes:
            if text_lower.endswith(suffix):
                return True
        
        # Check for common documentation patterns
        doc_patterns = [
            r"^<.*>$",  # <your-token-here>
            r"^\[.*\]$",  # [INSERT_KEY_HERE]
            r"^\{.*\}$",  # {API_KEY}
            r"^xxx+$",  # xxxx
            r"^\.{3,}$",  # ...
            r"^\*{3,}$",  # ***
        ]
        for pattern in doc_patterns:
            if re.match(pattern, text_lower):
                return True
        
        return False
    
    @staticmethod
    def is_binary_file(file_path: str) -> bool:
        """
        Check if file is a binary/media file that shouldn't contain real secrets.
        
        Args:
            file_path: Path to file
            
        Returns:
            bool: True if file is binary/media type
        """
        if not file_path:
            return False
        
        path_lower = file_path.lower()
        
        # Check extension
        for ext in BINARY_FILE_EXTENSIONS:
            if path_lower.endswith(ext):
                return True
        
        return False
    
    @staticmethod
    def is_known_example_secret(text: str) -> bool:
        """
        Check if text matches known example secrets from documentation.
        
        These are specific values like AKIAIOSFODNN7EXAMPLE from AWS docs,
        or example JWT tokens from jwt.io.
        
        Args:
            text: Secret value to check
            
        Returns:
            bool: True if matches known documentation example
        """
        if not text:
            return False
        
        text_lower = text.lower().strip()
        
        # Direct match
        if text_lower in KNOWN_EXAMPLE_SECRETS:
            return True
        
        # Check if secret contains known example parts
        for example in KNOWN_EXAMPLE_SECRETS:
            if example in text_lower:
                return True
            if text_lower in example and len(text_lower) > 10:
                return True
        
        return False
    
    @staticmethod
    def is_template_config_file(file_path: str) -> bool:
        """
        Check if file is a template/example configuration file.
        
        Files like .env.example, config.sample.json are templates,
        not actual configuration files.
        
        Args:
            file_path: Path to file
            
        Returns:
            bool: True if file is a template configuration
        """
        if not file_path:
            return False
        
        file_lower = file_path.lower()
        
        # Check for template patterns in filename
        for pattern in TEMPLATE_CONFIG_PATTERNS:
            if pattern in file_lower:
                return True
        
        return False
    
    @staticmethod
    def is_tutorial_repository(repo_name: str) -> bool:
        """
        Check if repository name suggests it's a tutorial/learning project.
        
        Repositories named 'learn-python', 'tutorial-express', etc.
        are highly likely to contain example secrets, not real ones.
        
        Args:
            repo_name: Repository name to check
            
        Returns:
            bool: True if repository appears to be tutorial/learning project
        """
        if not repo_name:
            return False
        
        repo_lower = repo_name.lower()
        
        # Check for tutorial patterns
        for pattern in TUTORIAL_REPO_PATTERNS:
            if pattern in repo_lower:
                return True
        
        return False
    
    @staticmethod
    def contains_local_host(text: str) -> bool:
        """
        Check if text contains local/development host references.
        
        Secrets referencing localhost, 127.0.0.1, etc. are
        development configurations, not production leaks.
        
        Args:
            text: Text to check (could be URL, connection string, etc.)
            
        Returns:
            bool: True if contains local/development hosts
        """
        if not text:
            return False
        
        text_lower = text.lower()
        
        for host in LOCAL_HOST_PATTERNS:
            if host in text_lower:
                return True
        
        return False
    
    @staticmethod
    def is_mock_data_path(file_path: str) -> bool:
        """
        Check if file path indicates mock/fixture test data.
        
        Paths containing __mocks__, fixtures, stubs, etc.
        are test data, not production secrets.
        
        Args:
            file_path: Path to file
            
        Returns:
            bool: True if path indicates mock/fixture data
        """
        if not file_path:
            return False
        
        path_lower = file_path.lower()
        path_parts = set(re.split(r'[/\\]', path_lower))
        
        for pattern in MOCK_DATA_PATH_PATTERNS:
            if pattern in path_parts:
                return True
            # Also check if pattern is substring of path part
            if any(pattern in part for part in path_parts):
                return True
        
        return False
    
    @staticmethod
    def is_random_string_with_keyword(text: str, keywords: List[str], min_keyword_len: int = 3) -> bool:
        """
        Check if text is a random/encoded string that happens to contain a keyword.
        
        This detects cases like "JKNDsdkjndssdjunJDNdkjfnskn32984vtbdsjsd887Vtbkdjdsnks"
        where "vtb" appears by coincidence in what looks like base64/random data.
        
        Args:
            text: String to analyze
            keywords: List of keywords to check (e.g., company tokens)
            min_keyword_len: Minimum keyword length to consider
            
        Returns:
            bool: True if appears to be random string with accidental keyword match
        """
        if not text or len(text) < 25:  # Minimum length for random string detection
            return False
        
        text_stripped = text.strip()
        
        # Skip if it has meaningful structure (API key patterns)
        if LeakAnalyzer.has_meaningful_structure(text_stripped):
            return False
        
        # Check for random-looking strings (high entropy with no clear structure)
        # Count character types
        upper_count = sum(1 for c in text_stripped if c.isupper())
        lower_count = sum(1 for c in text_stripped if c.islower())
        digit_count = sum(1 for c in text_stripped if c.isdigit())
        
        total_alpha = upper_count + lower_count
        if total_alpha < 10:
            return False  # Not enough letters to analyze
        
        # Check for mixed case randomness (real tokens usually have consistent patterns)
        upper_ratio = upper_count / total_alpha if total_alpha > 0 else 0
        
        # Random strings often have chaotic mix of upper/lower (unlike structured API keys)
        is_chaotic_case = 0.15 < upper_ratio < 0.85
        
        if is_chaotic_case:
            # Check if it has embedded keywords in suspicious context
            for keyword in keywords:
                if len(keyword) >= min_keyword_len:
                    keyword_lower = keyword.lower()
                    text_lower = text_stripped.lower()
                    if keyword_lower in text_lower:
                        idx = text_lower.find(keyword_lower)
                        
                        # Check context: keyword should be surrounded by random chars
                        before = text_lower[max(0, idx-5):idx]
                        after = text_lower[idx+len(keyword_lower):idx+len(keyword_lower)+5]
                        
                        # If keyword is NOT at word boundary and surrounded by alphanumeric
                        has_alpha_before = any(c.isalnum() for c in before) if before else False
                        has_alpha_after = any(c.isalnum() for c in after) if after else False
                        
                        # If both sides have alphanumeric (not separators), it's embedded in gibberish
                        if has_alpha_before and has_alpha_after:
                            # Additional check: ensure it's not a valid key pattern like "vtb_key"
                            if before and after:
                                # Not at word boundary
                                if before[-1].isalnum() or after[0].isalnum():
                                    return True
        
        return False
    
    @staticmethod
    def looks_like_encoded_data(text: str) -> bool:
        """
        Check if text looks like encoded/serialized data (base64, hex, etc.)
        rather than a meaningful secret.
        
        Note: This is conservative - only flags obvious encoded data, not API keys.
        
        Args:
            text: String to analyze
            
        Returns:
            bool: True if looks like encoded data
        """
        if not text:
            return False
        
        text_stripped = text.strip()
        
        # UUID format (36 chars with dashes) - check first before length check
        if UUID_PATTERN.match(text_stripped):
            return True
        
        # Minimum length for other checks
        if len(text_stripped) < 30:
            return False
        
        # Skip if it has known API key structure
        if LeakAnalyzer.has_meaningful_structure(text_stripped):
            return False
        
        # Very long pure hex string (likely hash or binary data)
        if HEX_PATTERN.match(text_stripped) and len(text_stripped) >= 40:
            # Common hash lengths: SHA1=40, SHA256=64, SHA512=128
            if len(text_stripped) in [40, 64, 128]:
                return True  # Likely a hash, not a secret
        
        # Very long string with no spaces/separators (likely serialized data)
        if len(text_stripped) > 200 and ' ' not in text_stripped and '\n' not in text_stripped:
            # Check if it's pure alphanumeric (no structure)
            alnum_ratio = sum(1 for c in text_stripped if c.isalnum()) / len(text_stripped)
            if alnum_ratio > 0.95:
                return True
        
        # Long base64 with padding (likely encoded binary data)
        if len(text_stripped) > 100 and text_stripped.endswith('=='):
            if BASE64_PATTERN.match(text_stripped):
                return True
        
        return False
    
    @staticmethod
    def has_meaningful_structure(text: str) -> bool:
        """
        Check if text has meaningful structure typical of real secrets.
        
        Real secrets often have:
        - Prefixes (sk_, pk_, ghp_, AKIA, etc.)
        - Separators (-, _, .)
        - Consistent patterns
        
        Args:
            text: String to analyze
            
        Returns:
            bool: True if has meaningful structure
        """
        if not text or len(text) < 8:
            return False
        
        text_stripped = text.strip()
        
        # Known prefixes indicate real secrets
        known_prefixes = [
            "sk_", "pk_", "rk_",  # Stripe
            "ghp_", "gho_", "ghu_", "ghs_",  # GitHub
            "xox", "xoxb", "xoxp",  # Slack
            "AKIA", "ABIA", "ACCA", "ASIA",  # AWS
            "eyJ",  # JWT
            "bearer ", "Bearer ",
            "api_", "api-",
            "key_", "key-",
            "token_", "token-",
            "secret_", "secret-",
            "-----BEGIN",  # PEM
        ]
        
        for prefix in known_prefixes:
            if text_stripped.startswith(prefix):
                return True
        
        # Check for key=value or key: value patterns
        if re.match(r'^[\w-]+\s*[:=]\s*.+$', text_stripped):
            return True
        
        # Check for consistent separator usage
        separators = ['-', '_', '.']
        for sep in separators:
            parts = text_stripped.split(sep)
            if 2 <= len(parts) <= 6:
                # Multiple parts with separator = structured
                if all(len(p) >= 2 for p in parts):
                    return True
        
        return False
    
    def _is_false_positive_path(self, file_path: str) -> bool:
        """
        Check if file path indicates likely false positive (test/example files).
        
        Args:
            file_path: Path to file
            
        Returns:
            bool: True if path suggests false positive
        """
        if not file_path:
            return False
        
        path_lower = file_path.lower()
        path_parts = set(re.split(r'[/\\]', path_lower))
        
        # Check for false positive directory patterns
        for pattern in FALSE_POSITIVE_PATH_PATTERNS:
            if pattern in path_parts:
                return True
            # Also check if pattern is part of a directory name
            if any(pattern in part for part in path_parts):
                return True
        
        # Check file name patterns
        file_name = path_parts.pop() if path_parts else ""
        fp_file_patterns = [
            r"test_.*", r".*_test\.", r".*\.test\.", r".*\.spec\.",
            r"example.*", r"sample.*", r"demo.*", r"mock.*",
            r"fixture.*", r".*_mock\.", r".*_stub\.",
        ]
        for pattern in fp_file_patterns:
            if re.match(pattern, file_name):
                return True
        
        return False
    
    def _calculate_secret_entropy_score(self, secret_value: str, secret_type: str) -> float:
        """
        Calculate score based on entropy analysis.
        
        Args:
            secret_value: The secret string
            secret_type: Type of secret
            
        Returns:
            float: Score from 0.0 to 1.0
        """
        if not secret_value:
            return 0.0
        
        entropy = self.calculate_entropy(secret_value)
        min_entropy = MIN_ENTROPY_THRESHOLDS.get(secret_type, MIN_ENTROPY_THRESHOLDS["default"])
        
        if entropy < min_entropy:
            # Low entropy - likely fake/simple value
            return max(0.0, entropy / min_entropy * 0.5)
        elif entropy >= min_entropy and entropy < min_entropy + 1.0:
            # Medium entropy - could be real or fake
            return 0.5 + (entropy - min_entropy) * 0.3
        else:
            # High entropy - likely real secret
            return min(1.0, 0.8 + (entropy - min_entropy - 1.0) * 0.1)
    
    @property
    def corporate_domain_patterns(self) -> dict:
        """?????????????? ?????????????????????????? ?????????????????? ?????????????????????????? ??????????????."""
        if self._corporate_domain_patterns is None:
            self._corporate_domain_patterns = self._generate_corporate_domain_patterns()
        return self._corporate_domain_patterns
    
    @classmethod
    def _get_compiled_pattern(cls, pattern: str, flags: int = 0) -> re.Pattern:
        """
        ???????????????????? ???????????????????????????????? regex ?????????????? ???? ???????? ?????? ?????????????????????? ??????????.
        
        Args:
            pattern: ???????????? ?????????????????????? ??????????????????
            flags: ?????????? ???????????????????? regex
            
        Returns:
            ???????????????????????????????? re.Pattern
        """
        cache_key = f"{pattern}:{flags}"
        if cache_key not in cls._compiled_patterns_cache:
            cls._compiled_patterns_cache[cache_key] = re.compile(pattern, flags)
        return cls._compiled_patterns_cache[cache_key]
    
    @classmethod
    def clear_pattern_cache(cls):
        """?????????????? ???????? ?????????????????? (?????? ???????????????????????? ?????? ???????????????????????? ????????????)."""
        cls._compiled_patterns_cache.clear()
        cls._domain_patterns_cache.clear()

    def _generate_corporate_domain_patterns(self) -> dict:
        """Generate corporate domain patterns based on company name and dork."""
        patterns = {}
        
        # Get company tokens
        company_tokens = self.company_tokens
        
        # Add dork as additional token if it exists
        dork_tokens = []
        if self.leak_obj.dork:
            dork_tokens = re.split(r"[\s,._-]+", self.leak_obj.dork.lower())
            dork_tokens = [t for t in dork_tokens if t and len(t) > 2]  # Filter short tokens
        
        # Combine all relevant tokens
        all_tokens = list(set(company_tokens + dork_tokens))
        
        # Generate patterns for each token
        for token in all_tokens:
            if len(token) < 3:  # Skip very short tokens
                continue
                
            token_patterns = []
            
            # Common domain patterns
            common_tlds = [r"\.com$", r"\.ru$", r"\.org$", r"\.net$", r"\.io$", r"\.gov$"]
            
            # Direct domain patterns
            for tld in common_tlds:
                token_patterns.append(f"{re.escape(token)}{tld}")
            
            # Subdomain patterns
            for tld in common_tlds:
                token_patterns.append(f"\\.{re.escape(token)}{tld}")
            
            # Common corporate variations
            variations = [
                f"{token}corp", f"{token}group", f"{token}ltd", f"{token}inc",
                f"{token}bank", f"{token}tech", f"{token}dev", f"{token}it"
            ]
            
            for variation in variations:
                for tld in common_tlds:
                    token_patterns.append(f"{re.escape(variation)}{tld}")
            
            # Hyphenated versions
            if len(token) > 4:
                for tld in common_tlds:
                    token_patterns.append(f"{re.escape(token)}-.*{tld}")
                    token_patterns.append(f".*-{re.escape(token)}{tld}")
            
            patterns[token] = token_patterns
        
        return patterns
    
    def _extract_file_paths_from_secrets(self) -> list[str]:
        """Extract file paths from found secrets across all scanners."""
        file_paths = []
        
        for scanner_type in ["gitleaks", "gitsecrets", "trufflehog", "deepsecrets", "grepscan", "ioc_finder"]:
            if scanner_type in self.leak_obj.secrets and isinstance(self.leak_obj.secrets[scanner_type], constants.AutoVivification):
                for leak_id, leak_data in self.leak_obj.secrets[scanner_type].items():
                    # Extract file path from leak data
                    if isinstance(leak_data, dict):
                        file_path = leak_data.get("File", "") or leak_data.get("file", "") or leak_data.get("path", "")
                        if file_path:
                            file_paths.append(file_path.lower())
        
        return file_paths
    
    def _analyze_file_paths_relevance(self, company_tokens: list[str]) -> float:
        """
        Analyze file paths for company relevance.
        
        Enhanced with false positive path detection.
        """
        file_paths = self._extract_file_paths_from_secrets()
        if not file_paths or not company_tokens:
            return 0.0
            
        score = 0.0
        fp_path_count = 0
        
        for file_path in file_paths:
            # Check for false positive paths first
            if self._is_false_positive_path(file_path):
                fp_path_count += 1
                score -= 0.1  # Penalty for secrets in test/example paths
                continue
            
            # Check for framework configuration patterns (often false positive)
            if self._is_framework_config_path(file_path):
                score -= 0.05
                continue
            
            # Check for company tokens in package/namespace structure
            path_parts = re.split(r'[/\\.]', file_path)
            
            for token in company_tokens:
                # Strong signal: company name in package structure
                if any(token in part for part in path_parts):
                    # Higher weight for deeper package structures
                    if any(part == token for part in path_parts):  # Exact match
                        score += 0.4
                    else:  # Partial match
                        score += 0.2
                
                # Very strong signal: company domain in reverse package structure
                if f"com/{token}" in file_path or f"com.{token}" in file_path:
                    score += 0.5
                    
                # Strong signal: company name in critical files
                critical_patterns = [
                    f"{token}.*config", f"{token}.*properties", f"{token}.*credentials",
                    f"{token}.*auth", f"{token}.*secret", f"{token}.*key"
                ]
                if any(re.search(pattern, file_path) for pattern in critical_patterns):
                    score += 0.3
                    
            # File extension penalties - ???????????????????? BINARY_FILE_EXTENSIONS ???? constants
            if self.is_binary_file(file_path):
                score -= 0.3
            elif self.bad_file_ext:
                score -= 0.5
        
        # Apply aggregate penalty if most paths are FP
        if len(file_paths) > 0 and fp_path_count / len(file_paths) > 0.5:
            score *= 0.5
                
        return max(0.0, min(score, 1.0))
    
    def _is_framework_config_path(self, file_path: str) -> bool:
        """
        Check if file path is a typical framework configuration file.
        
        These often contain example/template secrets.
        
        Args:
            file_path: Path to check
            
        Returns:
            bool: True if likely framework config
        """
        if not file_path:
            return False
        
        path_lower = file_path.lower()
        
        # Framework-specific config patterns
        framework_patterns = [
            # Node.js / JavaScript
            "package.json", "package-lock.json", "yarn.lock",
            ".npmrc", ".yarnrc", "tsconfig.json", "webpack.config",
            ".eslintrc", ".prettierrc", "babel.config",
            
            # Python
            "requirements.txt", "setup.py", "setup.cfg", "pyproject.toml",
            "pipfile", "pipfile.lock", "tox.ini", ".flake8",
            
            # Ruby
            "gemfile", "gemfile.lock", ".rubocop",
            
            # Java / Kotlin / Gradle
            "pom.xml", "build.gradle", "settings.gradle",
            "gradle.properties",
            
            # Go
            "go.mod", "go.sum",
            
            # Docker / CI
            "dockerfile", "docker-compose", ".dockerignore",
            ".travis.yml", ".circleci", ".github/workflows",
            "jenkinsfile", ".gitlab-ci",
            
            # IDE / Editor
            ".vscode/", ".idea/", ".editorconfig",
            
            # Documentation
            "contributing.md", "readme.md", "changelog.md",
            "license", "authors",
        ]
        
        for pattern in framework_patterns:
            if pattern in path_lower:
                return True
        
        # Check for framework directories
        for framework in FRAMEWORK_CONFIG_PATTERNS:
            if f"/{framework}/" in path_lower or f"\\{framework}\\" in path_lower:
                return True
        
        return False
    
    def _extract_domain_from_email(self, email: str) -> str:
        """Extract domain from email address."""
        if not email or '@' not in email:
            return ""
        
        try:
            domain = email.split('@')[-1].lower().strip()
            return domain
        except (IndexError, AttributeError) as e:
            logger.warning(f"Error extracting domain from email '{email}': {e}")
            return ""
    
    def _check_corporate_email_domains(self, email: str, company_tokens: list[str]) -> float:
        """Check if email belongs to corporate domain."""
        if not email or not company_tokens:
            return 0.0
            
        email_lower = email.lower()
        score = 0.0
        
        # Extract domain using simple function
        domain = self._extract_domain_from_email(email_lower)
        if not domain:
            return 0.0
        
        # Check against known corporate domains based on company tokens
        for token in company_tokens:
            if token in self.corporate_domain_patterns:
                patterns = self.corporate_domain_patterns[token]
                for pattern in patterns:
                    if re.search(pattern, domain):
                        return 1.0  # Perfect match for corporate domain
        
        # Check for company tokens in domain
        for token in company_tokens:
            if token in domain:
                score += 0.7
        
        # Penalty for common public domains
        public_domains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]
        for pub_domain in public_domains:
            if pub_domain in domain:
                score -= 0.2
            
        return max(score, 0.0)
    
    def _is_repository_fork(self) -> bool:
        """Check if repository is a fork."""
        return bool(self.leak_obj.stats.repo_stats_leak_stats_table.get("fork", False))
    
    def _calculate_fork_penalty(self) -> float:
        """Calculate penalty for fork repositories."""
        if not self._is_repository_fork():
            return 0.0
            
        # Check if fork has significant original commits
        commits_count = self.leak_obj.stats.repo_stats_leak_stats_table.get('commits_count', 0)
        forks_count = self.leak_obj.stats.repo_stats_leak_stats_table.get('forks_count', 0)
        
        # If fork has many commits relative to popularity, it might have original content
        if commits_count > 100 and forks_count < 10:
            return 0.1  # Small penalty for active forks
        else:
            return 0.3  # Larger penalty for typical forks
    
    def _get_repo_stats(self) -> dict:
        """Get repository statistics dictionary."""
        return self.leak_obj.stats.repo_stats_leak_stats_table or {}
    
    def _is_tiny_repository(self) -> bool:
        """
        Check if repository is very small (likely test/example).
        
        Returns:
            bool: True if repository size < REPO_SIZE_TINY_KB
        """
        stats = self._get_repo_stats()
        size_kb = stats.get('size', 0)  # Size in KB from GitHub API
        return size_kb < REPO_SIZE_TINY_KB
    
    def _is_small_repository(self) -> bool:
        """
        Check if repository is small (possibly personal/test project).
        
        Returns:
            bool: True if repository size < REPO_SIZE_SMALL_KB
        """
        stats = self._get_repo_stats()
        size_kb = stats.get('size', 0)
        return size_kb < REPO_SIZE_SMALL_KB
    
    def _is_likely_personal_project(self) -> bool:
        """
        Check if repository appears to be a personal/hobby project.
        
        Indicators:
        - Small size
        - Few stars/forks
        - Single contributor
        - Low commit count
        
        Returns:
            bool: True if likely personal project
        """
        stats = self._get_repo_stats()
        
        stars = stats.get('stargazers_count', 0)
        forks = stats.get('forks_count', 0)
        contributors = stats.get('contributors_count', 0)
        commits = stats.get('commits_count', 0)
        size_kb = stats.get('size', 0)
        
        # Personal project indicators
        is_small = size_kb < REPO_SIZE_SMALL_KB
        low_popularity = stars <= REPO_MAX_STARS_FOR_PERSONAL and forks <= 2
        single_contributor = contributors <= 1
        
        # Count how many indicators match
        indicators = sum([is_small, low_popularity, single_contributor])
        
        return indicators >= 3  # At least 3 indicators
    
    def _is_highly_popular_repository(self) -> bool:
        """
        Check if repository is highly popular (likely well-known OSS).
        
        Popular repositories with secrets are usually:
        - Well-known OSS projects with example configs
        - Documentation/tutorial repos
        
        Returns:
            bool: True if repository is highly popular
        """
        stats = self._get_repo_stats()
        
        stars = stats.get('stargazers_count', 0)
        forks = stats.get('forks_count', 0)
        contributors = stats.get('contributors_count', 0)
        
        return (
            stars >= REPO_STARS_HIGH or
            forks >= REPO_FORKS_HIGH or
            contributors >= REPO_CONTRIBUTORS_HIGH
        )
    
    def _is_very_popular_repository(self) -> bool:
        """
        Check if repository is extremely popular.
        
        Returns:
            bool: True if stars >= REPO_STARS_VERY_HIGH
        """
        stats = self._get_repo_stats()
        return stats.get('stargazers_count', 0) >= REPO_STARS_VERY_HIGH

    
    def _all_committers_use_public_email(self) -> bool:
        """
        Check if all committers use public email domains.
        
        If all committers use gmail/hotmail/etc, it's likely a personal project.
        
        Returns:
            bool: True if all committers use public email domains
        """
        committers = self.leak_obj.stats.commits_stats_commiters_table or []
        
        if not committers:
            return False  # No data to analyze
        
        public_domains = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
                        "mail.ru", "yandex.ru", "qq.com", "163.com", "126.com",
                        "protonmail.com", "icloud.com", "live.com", "msn.com"}
        
        for committer in committers:
            email = committer.get('commiter_email', '')
            if '@' in email:
                domain = email.split('@')[-1].lower()
                if domain not in public_domains:
                    return False  # Found corporate/private email
        
        return True  # All emails are public
    
    def _has_corporate_committer(self) -> bool:
        """
        Check if any committer uses a corporate email domain.
        
        Corporate email = higher chance of real leak.
        
        Returns:
            bool: True if at least one committer has corporate email
        """
        corporate_committers = self.get_corporate_committers()
        return len(corporate_committers) > 0
    
    def get_corporate_committers(self) -> List[dict]:
        """
        Get list of committers with corporate (non-public) email domains.
        
        This is a CRITICAL signal for leak relevance - corporate emails
        strongly indicate the code belongs to the target company.
        
        Returns:
            List[dict]: List of committers with corporate emails, each containing:
                - commiter_name: str
                - commiter_email: str  
                - domain: str (email domain)
                - matches_company: bool (True if domain matches company tokens)
        """
        committers = self.leak_obj.stats.commits_stats_commiters_table or []
        corporate_committers = []
        
        public_domains = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
                        "mail.ru", "yandex.ru", "qq.com", "163.com", "126.com",
                        "protonmail.com", "icloud.com", "live.com", "msn.com",
                        "aol.com", "zoho.com", "gmx.com", "fastmail.com"}
        
        company_tokens = self.company_tokens
        
        for committer in committers:
            email = committer.get('commiter_email', '')
            if '@' in email:
                domain = email.split('@')[-1].lower()
                if domain not in public_domains:
                    # Check if domain matches company
                    matches_company = any(
                        token in domain for token in company_tokens
                    ) if company_tokens else False
                    
                    corporate_committers.append({
                        "commiter_name": committer.get('commiter_name', ''),
                        "commiter_email": email,
                        "domain": domain,
                        "matches_company": matches_company
                    })
        
        return corporate_committers
    
    def has_target_company_committer(self) -> bool:
        """
        Check if any committer has email from target company domain.
        
        This is the STRONGEST signal for leak relevance.
        Example: searching for "vtb" and finding committer@vtb.ru
        
        Returns:
            bool: True if committer email domain matches company tokens
        """
        corporate_committers = self.get_corporate_committers()
        return any(c.get('matches_company', False) for c in corporate_committers)
    
    def _calculate_repo_credibility_score(self) -> float:
        """
        Calculate repository credibility score based on statistics.
        
        Higher score = more likely to contain real secrets.
        Lower score = more likely to be test/example/personal project.
        
        CRITICAL: Corporate emails from target company are strongest signal!
        
        Returns:
            float: Score from 0.0 to 1.0
        """
        score = 0.5  # Start neutral
        stats = self._get_repo_stats()
        
        # ===== STRONGEST SIGNAL: Target company email =====
        # If committer email matches company domain (e.g., dev@vtb.ru for VTB)
        # this is almost certainly a real leak from the target company
        if self.has_target_company_committer():
            score += 0.45  # Very strong boost - almost guaranteed relevance
        # Any corporate email (not public like gmail) is also strong signal
        elif self._has_corporate_committer():
            score += 0.25  # Good boost for any corporate email
        elif self._all_committers_use_public_email():
            score -= 0.1  # Slight penalty for all public emails
        
        # Tiny repository penalty
        if self._is_tiny_repository():
            score -= 0.2
        elif self._is_small_repository():
            score -= 0.1
        
        # Personal project penalty (but not if we have corporate committer!)
        if self._is_likely_personal_project() and not self._has_corporate_committer():
            score -= 0.15
        
        # Very popular = likely OSS with examples (slight penalty)
        if self._is_very_popular_repository():
            score -= 0.1
        elif self._is_highly_popular_repository():
            score -= 0.05
        
        # Fork penalty (reuse existing method)
        score -= self._calculate_fork_penalty()
        
        # Clamp to [0, 1]
        return max(0.0, min(1.0, score))

    def calculate_organization_relevance_score(self) -> float:
        score = 0.0
        dork = (self.leak_obj.dork or "").lower()
        description = str(self.leak_obj.stats.repo_stats_leak_stats_table.get("description") or "")
        company_tokens = self.company_tokens
        
        # Factor 1: Dork relevance
        # If the dork is found in the repo name or description, it's highly relevant
        if dork and self.leak_obj.repo_name and dork in self.leak_obj.repo_name.lower():
            score += 0.25
        if dork and description and dork in description.lower():
            score += 0.15
        
        # Check other company tokens in description
        if company_tokens and description:
            description_lower = description.lower()
            for token in company_tokens:
                if token in description_lower:
                    # Lower score than dork since these are derived tokens
                    score += 0.08
        # Factor 2: Enhanced Author/Committer relevance with corporate email analysis
        # Check if author or committers names/emails contain parts of the dork or company name
        if self.leak_obj.author_name and self.leak_obj.dork and self.leak_obj.dork.lower() in self.leak_obj.author_name.lower():
            score += 0.3
        
        # Enhanced committer analysis with corporate email checking
        for committer in self.leak_obj.stats.commits_stats_commiters_table:
            committer_name = committer.get("commiter_name", "")
            committer_email = committer.get("commiter_email", "")
            committer_info = f'{committer_name} {committer_email}'
            
            # Check for dork in committer info
            if self.leak_obj.dork and self.leak_obj.dork.lower() in committer_info.lower():
                score += 0.1
            
            # Check for company tokens in committer info
            if company_tokens and any(tok in committer_info.lower() for tok in company_tokens):
                score += 0.15
                
            # NEW: Corporate email domain analysis
            email_score = self._check_corporate_email_domains(committer_email, company_tokens)
            score += email_score * 0.4  # High weight for corporate emails
        
        # Factor 3: Enhanced Company name heuristics with file path analysis
        if company_tokens:
            repo_name_l = (self.leak_obj.repo_name or "").lower()
            topics = str(self.leak_obj.stats.repo_stats_leak_stats_table.get("topics") or "").lower()
            
            if any(tok in repo_name_l for tok in company_tokens):
                score += 0.3
            if description and any(tok in description.lower() for tok in company_tokens):
                score += 0.1
            if topics and any(tok in topics for tok in company_tokens):
                score += 0.05
                
            # NEW: File path analysis
            file_path_score = self._analyze_file_paths_relevance(company_tokens)
            score += file_path_score * 0.35  # High weight for file path relevance
            
        # Factor 4: Country profiling (existing logic)
        if constants.COUNTRY_PROFILING:
            company_country = constants.COMPANY_COUNTRY_MAP_DEFAULT
            if self.leak_obj.company_id in constants.COMPANY_COUNTRY_MAP:
                company_country = constants.COMPANY_COUNTRY_MAP[self.leak_obj.company_id]
                
            if company_country == "ru":
                # Cyrillic names or .ru emails/descriptions slightly increase relevance
                if re.search(r"[??-????-??]", self.leak_obj.author_name or ""):
                    score += 0.05
                if re.search(r"[??-????-??]", description):
                    score += 0.05
                for committer in self.leak_obj.stats.commits_stats_commiters_table:
                    if re.search(r"[??-????-??]", committer.get('commiter_name', '')):
                        score += 0.05
                    if committer.get('commiter_email', '').lower().endswith('.ru'):
                        score += 0.05
                    if re.search(r"@.+\.(com|org|net|io)$", committer.get('commiter_email', '').lower()):
                        score -= 0.02
            elif company_country == "en":
                if re.fullmatch(r"[A-Za-z ._-]+", self.leak_obj.author_name or ""):
                    score += 0.03
                if re.fullmatch(r"[A-Za-z0-9 ,._-]+", description.strip()):
                    score += 0.03
                for committer in self.leak_obj.stats.commits_stats_commiters_table:
                    if re.fullmatch(r"[A-Za-z ._-]+", committer.get('commiter_name', '')):
                        score += 0.02
                    if re.search(r"@.+\.(com|org|net|io)$", committer.get('commiter_email', '').lower()):
                        score += 0.02
        
        # Factor 5: Enhanced popularity penalty with fork analysis
        stars = self.leak_obj.stats.repo_stats_leak_stats_table.get('stargazers_count', 0)
        commiters = self.leak_obj.stats.repo_stats_leak_stats_table.get('commiters_count', 0)
        if stars > 100:
            score -= 0.1
        if stars > 1000:
            score -= 0.15
        if commiters > 50:
            score -= 0.05
        if commiters > 200:
            score -= 0.15
            
        # NEW: Fork penalty
        fork_penalty = self._calculate_fork_penalty()
        score -= fork_penalty
            
        # Factor 6: AI assessment (if available and positive)
        ai_analysis = getattr(self.leak_obj, 'ai_analysis', None)
        if ai_analysis and ai_analysis.get('company_relevance', {}).get('is_related'):
            ai_confidence = ai_analysis.get('company_relevance', {}).get('confidence', 0.0)
            score += ai_confidence * 0.5 + 0.1  # Weighted boost based on AI confidence
        elif ai_analysis and not ai_analysis.get('company_relevance', {}).get('is_related'):
            ai_confidence = ai_analysis.get('company_relevance', {}).get('confidence', 0.0)
            score -= (ai_confidence * 0.3 + 0.05)  # Penalty based on AI confidence
            
        # Cap the score at 1.0
        score = max(score, 0.0)  # Ensure score is not negative
        score = round(score, 2)  # Round to 2 decimal places for consistency
        return min(score, 1.0)

    def _classify_secret_type(self, secret_data: dict) -> Tuple[str, float]:
        """
        Classify the type of secret and return its criticality weight.
        
        Enhanced version with better detection of test/dummy secrets.
        
        Args:
            secret_data: Dictionary with secret data
            
        Returns:
            Tuple[str, float]: (secret_type, criticality_weight)
        """
        if not isinstance(secret_data, dict):
            return "unknown", 0.1
            
        # Get relevant fields from secret data
        rule_name = str(secret_data.get("RuleID", "") or secret_data.get("rule", "") or secret_data.get("Rule", "") or "").lower()
        match_text = str(secret_data.get("Match", "") or secret_data.get("match", "") or secret_data.get("Secret", "") or "").lower()
        file_path = str(secret_data.get("File", "") or secret_data.get("file", "") or secret_data.get("path", "") or "").lower()
        
        # Combine all text for analysis
        combined_text = f"{rule_name} {match_text} {file_path}"
        
        # ===== EARLY FALSE POSITIVE DETECTION =====
        # Check for test/example indicators FIRST
        test_indicators = ["test_", "test-", "_test", "-test", "example_", "example-", 
                         "_example", "sample_", "sample-", "demo_", "demo-", 
                         "dummy_", "fake_", "mock_"]
        
        for indicator in test_indicators:
            if indicator in combined_text:
                # Check if it's a test/dummy type
                if any(p in combined_text for p in ["password", "pass", "pwd", "secret", "key", "token"]):
                    return "dummy_password", 0.05
        
        # Check for common test file patterns
        test_path_patterns = ["/test/", "/tests/", "/spec/", "/example/", "/examples/", 
                            "/sample/", "/demo/", "/fixture/", "/mock/"]
        if any(p in file_path for p in test_path_patterns):
            # Reduce weight for secrets in test paths
            weight_multiplier = 0.3
        else:
            weight_multiplier = 1.0
        
        # ===== TYPE CLASSIFICATION =====
        # Check for specific high-value patterns first (order matters)
        
        # AWS credentials - highest priority
        if "akia" in match_text or "aws_access" in combined_text or "aws_secret" in combined_text:
            return "aws_key", 0.95 * weight_multiplier
        
        # GitHub tokens
        if any(prefix in match_text for prefix in ["ghp_", "gho_", "ghu_", "ghs_"]):
            return "github_token", 0.95 * weight_multiplier
        
        # JWT tokens
        if match_text.startswith("eyj") or "jwt" in rule_name:
            return "jwt_token", 0.8 * weight_multiplier
        
        # Use the optimized dictionary for remaining classifications
        for secret_type, (patterns, base_weight) in SECRET_CLASSIFICATION.items():
            if any(pattern in combined_text for pattern in patterns):
                # Apply test path weight multiplier
                final_weight = base_weight * weight_multiplier
                
                # Further reduce weight for known low-value types
                if secret_type in ["test_password", "dev_password", "dummy_password"]:
                    final_weight = min(final_weight, 0.1)
                
                return secret_type, final_weight
        
        return "unknown", 0.3 * weight_multiplier
    
    def _analyze_secret_context(self, secret_data: dict) -> float:
        """
        Analyze the context around a secret to determine its criticality.
        
        Enhanced version with better false positive detection.
        """
        if not isinstance(secret_data, dict):
            return 0.0
            
        context_score = 0.0
        
        # Get context fields
        file_path = str(secret_data.get("File", "") or secret_data.get("file", "") or secret_data.get("path", "") or "").lower()
        line_before = str(secret_data.get("LineBefore", "") or secret_data.get("line_before", "") or "").lower()
        line_after = str(secret_data.get("LineAfter", "") or secret_data.get("line_after", "") or "").lower()
        match_text = str(secret_data.get("Match", "") or secret_data.get("match", "") or secret_data.get("Secret", "") or "").lower()
        
        # Combine context
        context = f"{file_path} {line_before} {line_after} {match_text}"
        
        # Check for critical context keywords
        for keyword, weight in self.context_keywords["critical"].items():
            if keyword in context:
                context_score += weight
        
        # Check for negative context keywords
        for keyword, weight in self.context_keywords["negative"].items():
            if keyword in context:
                context_score += weight  # weight is negative
        
        # ENHANCED: File path analysis for false positives
        if self._is_false_positive_path(file_path):
            context_score -= 0.4  # Strong penalty for test/example paths
        
        # File path analysis - positive signals
        if any(path in file_path for path in ["config", "properties", ".env", "secret", "credential"]):
            context_score += 0.2
        if any(path in file_path for path in [".prod", "production", "live", "deploy"]):
            context_score += 0.25
            
        # ENHANCED: Check for documentation context
        doc_indicators = ["readme", "changelog", "contributing", "license", "authors", ".md", ".rst", ".txt"]
        if any(indicator in file_path for indicator in doc_indicators):
            context_score -= 0.3
        
        # ENHANCED: Check for comment patterns in context (suggests documentation, not real secret)
        comment_patterns = [r"#\s*example", r"//\s*example", r"/\*", r"\*/", r"<!--", r"-->", r"todo:", r"fixme:"]
        for pattern in comment_patterns:
            if re.search(pattern, context):
                context_score -= 0.15
        
        return context_score
    
    def _validate_secret_format(self, secret_data: dict, secret_type: str) -> float:
        """
        Enhanced validation of secret format to determine if it's likely real or fake.
        
        Uses entropy analysis, pattern matching, and format validation.
        Includes detection of random strings with accidental keyword matches.
        
        Args:
            secret_data: Dictionary with secret data
            secret_type: Classified type of secret
            
        Returns:
            float: Validation score from 0.0 (fake) to 1.0 (likely real)
        """
        if not isinstance(secret_data, dict):
            return 0.3
            
        match_text = str(secret_data.get("Match", "") or secret_data.get("match", "") or secret_data.get("Secret", "") or "")
        file_path = str(secret_data.get("File", "") or secret_data.get("file", "") or secret_data.get("path", "") or "")
        
        # Start with neutral score
        validation_score = 0.5
        
        # ===== BINARY FILE CHECK (highest priority) =====
        if self.is_binary_file(file_path):
            return 0.02  # Almost certainly not a real secret source
        
        # ===== KNOWN DOCUMENTATION EXAMPLE CHECK =====
        if self.is_known_example_secret(match_text):
            return 0.03  # Known documentation example (AKIAIOSFODNN7EXAMPLE, etc.)
        
        # ===== PLACEHOLDER CHECK (strong signal for FP) =====
        if self.is_known_placeholder(match_text):
            return 0.05  # Almost certainly false positive
        
        # ===== TEMPLATE CONFIG FILE CHECK =====
        if self.is_template_config_file(file_path):
            validation_score *= 0.2  # High penalty for .example, .sample files
        
        # ===== MOCK/FIXTURE DATA PATH CHECK =====
        if self.is_mock_data_path(file_path):
            validation_score *= 0.25  # High penalty for mock/fixture directories
        
        # ===== LOCAL HOST CHECK =====
        if self.contains_local_host(match_text):
            validation_score *= 0.3  # Development/local config, not production leak
        
        # ===== RANDOM STRING WITH KEYWORD CHECK =====
        # Detect cases like "JKNDsdkjndssdjunJDNdkjfnskn32984vtbdsjsd887Vtb"
        if self.is_random_string_with_keyword(match_text, self.company_tokens):
            return 0.03  # Company name appears randomly in gibberish
        
        # ===== ENCODED DATA CHECK =====
        if self.looks_like_encoded_data(match_text):
            # Check if it has meaningful structure despite being encoded-looking
            if not self.has_meaningful_structure(match_text):
                return 0.1  # Looks like base64/hex data, not a secret
        
        # ===== REPETITIVE PATTERN CHECK =====
        if self.has_repetitive_pattern(match_text):
            validation_score *= 0.3  # Strong penalty
        
        # ===== ENTROPY ANALYSIS =====
        entropy_score = self._calculate_secret_entropy_score(match_text, secret_type)
        
        # ===== FORMAT VALIDATION BY SECRET TYPE =====
        type_validation_score = self._validate_by_secret_type(match_text, secret_type)
        
        # ===== FILE PATH CONTEXT =====
        path_penalty = 0.0
        if self._is_false_positive_path(file_path):
            path_penalty = 0.3
        
        # ===== MEANINGFUL STRUCTURE BONUS =====
        structure_bonus = 0.0
        if self.has_meaningful_structure(match_text):
            structure_bonus = 0.15  # Bonus for secrets with known patterns
        
        # ===== REPOSITORY CREDIBILITY =====
        # Factor in repository statistics (size, activity, popularity, committers)
        repo_credibility = self._calculate_repo_credibility_score()
        
        # ===== COMBINE SCORES =====
        # Weight: entropy (30%), type validation (30%), repo credibility (20%), base (10%), structure (10%)
        validation_score = (
            entropy_score * 0.30 + 
            type_validation_score * 0.30 + 
            repo_credibility * 0.20 +
            validation_score * 0.10 +
            structure_bonus - 
            path_penalty
        )
        
        # ===== ADDITIONAL CHECKS =====
        match_lower = match_text.lower()
        
        # Check for obvious test/example patterns in the value itself
        fp_patterns = ["test", "example", "dummy", "fake", "sample", "demo", 
                      "placeholder", "changeme", "change_me", "your_", "xxx"]
        pattern_matches = sum(1 for p in fp_patterns if p in match_lower)
        if pattern_matches > 0:
            validation_score *= max(0.1, 1.0 - pattern_matches * 0.25)
        
        # Check for very short or very simple values
        if len(match_text) < 6:
            validation_score *= 0.3
        elif len(match_text) < 10 and match_text.isalnum():
            validation_score *= 0.6
        
        # Check for all same characters
        if len(set(match_text)) <= 2 and len(match_text) > 3:
            validation_score *= 0.1
        
        # ===== LONG RANDOM STRING PENALTY =====
        # Very long strings with mixed case and no structure are likely data, not secrets
        if len(match_text) > 50:
            if not self.has_meaningful_structure(match_text):
                # Check for signs of randomness
                upper_ratio = sum(1 for c in match_text if c.isupper()) / len(match_text)
                lower_ratio = sum(1 for c in match_text if c.islower()) / len(match_text)
                # Random mix of upper/lower (not consistent case)
                if 0.2 < upper_ratio < 0.8 and 0.2 < lower_ratio < 0.8:
                    validation_score *= 0.4
            
        return max(0.0, min(1.0, validation_score))
    
    def _validate_by_secret_type(self, match_text: str, secret_type: str) -> float:
        """
        Validate secret format based on its specific type.
        
        Args:
            match_text: The secret value
            secret_type: Type of secret
            
        Returns:
            float: Type-specific validation score
        """
        if not match_text:
            return 0.1
        
        match_lower = match_text.lower()
        score = 0.5  # Default neutral
        
        if secret_type == "private_key":
            # RSA/SSH keys should have specific structure
            if "-----BEGIN" in match_text and "-----END" in match_text:
                score = 0.95
            elif len(match_text) > 200:
                score = 0.7
            else:
                score = 0.3
                
        elif secret_type == "aws_key":
            # AWS keys have specific formats
            # Access Key ID: AKIA followed by 16 characters
            # Secret Access Key: 40 characters
            if re.match(r"^AKIA[A-Z0-9]{16}$", match_text):
                score = 0.95
            elif len(match_text) == 40 and re.match(r"^[A-Za-z0-9+/]+$", match_text):
                score = 0.85
            else:
                score = 0.4
                
        elif secret_type == "github_token":
            # GitHub tokens start with ghp_, gho_, ghu_, ghs_
            if re.match(r"^gh[pous]_[A-Za-z0-9]{36,}$", match_text):
                score = 0.95
            elif match_text.startswith(("ghp_", "gho_", "ghu_", "ghs_")):
                score = 0.8
            else:
                score = 0.3
                
        elif secret_type == "jwt_token":
            # JWT format: header.payload.signature
            parts = match_text.split(".")
            if len(parts) == 3 and all(len(p) > 10 for p in parts):
                score = 0.9
            elif match_lower.startswith("eyj"):  # Base64 encoded {"
                score = 0.8
            else:
                score = 0.4
                
        elif secret_type in ["api_key", "access_token", "secret_key"]:
            # API keys typically: 20+ chars, mix of letters/numbers
            length = len(match_text)
            has_letters = any(c.isalpha() for c in match_text)
            has_numbers = any(c.isdigit() for c in match_text)
            
            if length >= 32 and has_letters and has_numbers:
                score = 0.85
            elif length >= 20 and has_letters and has_numbers:
                score = 0.7
            elif length >= 16 and (has_letters or has_numbers):
                score = 0.55
            elif length < 12:
                score = 0.2
            else:
                score = 0.4
                
        elif secret_type == "password":
            # Passwords should have some complexity
            fake_passwords = {
                "password", "123456", "admin", "root", "test", "guest",
                "demo", "sample", "example", "default", "user", "pass",
                "password1", "password123", "admin123", "root123", "test123",
                "qwerty", "abc123", "letmein", "welcome", "monkey", "master",
            }
            if match_lower in fake_passwords:
                score = 0.05
            elif len(match_text) < 6:
                score = 0.15
            elif len(match_text) >= 12 and any(c.isupper() for c in match_text) and any(c.isdigit() for c in match_text):
                score = 0.75
            elif len(match_text) >= 8:
                score = 0.5
            else:
                score = 0.3
                
        elif secret_type in ["database_password", "prod_password", "admin_password"]:
            # These should have higher complexity
            if match_lower in KNOWN_PLACEHOLDER_PATTERNS:
                score = 0.05
            elif len(match_text) >= 16:
                score = 0.8
            elif len(match_text) >= 10:
                score = 0.6
            else:
                score = 0.3
                
        elif secret_type in ["test_password", "dev_password", "dummy_password"]:
            # These are almost always false positives
            score = 0.1
            
        elif secret_type == "certificate":
            if "-----BEGIN CERTIFICATE" in match_text:
                score = 0.9
            elif len(match_text) > 500:
                score = 0.7
            else:
                score = 0.4
        
        return score

    def calculate_sensitive_data_score(self) -> float:
        """
        Enhanced calculation of sensitive data score with detailed secret classification.
        
        Improvements for false positive reduction:
        - Entropy-based filtering
        - Per-secret false positive detection
        - Scanner correlation analysis
        - Aggregate false positive patterns detection
        """
        total_score = 0.0
        total_leaks = 0
        false_positive_count = 0
        high_confidence_secrets = 0
        
        # Track secret types and values for aggregate analysis
        secret_values_seen: Set[str] = set()
        secret_types_found: Dict[str, int] = {}
        
        # Enhanced scanner confidence weights
        scanner_base_weights = {
            "trufflehog": 0.9,    # Highest confidence
            "gitleaks": 0.8,      # High confidence
            "deepsecrets": 0.75,  # High confidence
            "gitsecrets": 0.6,    # Medium confidence
            "ioc_finder": 0.5,    # Medium confidence for IOCs
            "grepscan": 0.3,      # Lower confidence, depends on dork
        }

        for scanner_type, base_weight in scanner_base_weights.items():
            if scanner_type in self.leak_obj.secrets and isinstance(self.leak_obj.secrets[scanner_type], constants.AutoVivification):
                scanner_secrets = self.leak_obj.secrets[scanner_type]
                
                for leak_id, leak_data in scanner_secrets.items():
                    total_leaks += 1
                    
                    # Classify secret type and get its weight
                    secret_type, type_weight = self._classify_secret_type(leak_data)
                    secret_types_found[secret_type] = secret_types_found.get(secret_type, 0) + 1
                    
                    # Get secret value for deduplication and analysis
                    secret_value = str(leak_data.get("Match", "") or leak_data.get("match", "") or leak_data.get("Secret", "") or "")
                    file_path = str(leak_data.get("File", "") or leak_data.get("file", "") or leak_data.get("path", "") or "")
                    
                    # Skip duplicates (same secret found by multiple scanners)
                    value_hash = hash(secret_value[:100] if len(secret_value) > 100 else secret_value)
                    if value_hash in secret_values_seen:
                        continue
                    secret_values_seen.add(value_hash)
                    
                    # ===== ENHANCED FALSE POSITIVE DETECTION =====
                    
                    # Check if from binary file
                    if self.is_binary_file(file_path):
                        false_positive_count += 1
                        continue  # Skip secrets from binary files
                    
                    # Check if known placeholder
                    if self.is_known_placeholder(secret_value):
                        false_positive_count += 1
                        continue  # Skip this secret entirely
                    
                    # Check for random strings with accidental keyword matches
                    if self.is_random_string_with_keyword(secret_value, self.company_tokens):
                        false_positive_count += 1
                        continue  # Skip - company name appears randomly in gibberish
                    
                    # Check if it looks like encoded data without meaningful structure
                    if self.looks_like_encoded_data(secret_value) and not self.has_meaningful_structure(secret_value):
                        false_positive_count += 1
                        continue  # Skip - looks like base64/hex data, not a secret
                    
                    # Check for repetitive patterns
                    if self.has_repetitive_pattern(secret_value):
                        false_positive_count += 1
                        type_weight *= 0.2  # Heavy penalty
                    
                    # Entropy analysis
                    entropy = self.calculate_entropy(secret_value)
                    min_entropy = MIN_ENTROPY_THRESHOLDS.get(secret_type, MIN_ENTROPY_THRESHOLDS["default"])
                    
                    if entropy < min_entropy * 0.5:
                        # Very low entropy - almost certainly fake
                        false_positive_count += 1
                        continue
                    elif entropy < min_entropy:
                        # Low entropy - reduce weight
                        type_weight *= 0.4
                    
                    # ===== END FALSE POSITIVE DETECTION =====
                    
                    # Analyze context around the secret
                    context_score = self._analyze_secret_context(leak_data)
                    
                    # Validate secret format (now includes comprehensive FP detection)
                    validation_score = self._validate_secret_format(leak_data, secret_type)
                    
                    # If validation score is very low, count as FP
                    if validation_score < 0.15:
                        false_positive_count += 1
                        continue
                    
                    # Calculate final score for this secret
                    secret_score = base_weight * type_weight * validation_score
                    
                    # Apply context modifiers
                    secret_score += context_score * 0.3  # Reduced context influence
                    secret_score = max(0.0, secret_score)
                    
                    # Track high confidence secrets
                    if secret_score > 0.5:
                        high_confidence_secrets += 1
                    
                    total_score += secret_score
        
        # ===== AGGREGATE FALSE POSITIVE ANALYSIS =====
        
        # If most secrets are false positives, reduce overall score
        actual_secrets = total_leaks - false_positive_count
        if total_leaks > 0:
            fp_ratio = false_positive_count / total_leaks
            if fp_ratio > 0.8:
                # More than 80% FP - suspicious
                total_score *= 0.3
            elif fp_ratio > 0.5:
                # More than 50% FP - moderate concern
                total_score *= 0.6
        
        # If all secrets are of low-value types, reduce score
        low_value_types = {"test_password", "dev_password", "dummy_password"}
        if secret_types_found and all(t in low_value_types for t in secret_types_found.keys()):
            total_score *= 0.2
        
        # ===== NORMALIZE SCORE =====
        
        if actual_secrets > 0:
            # Use logarithmic scaling for diminishing returns
            normalized_score = total_score / (total_score + math.log(actual_secrets + 1) * 5)
            
            # Bonus for multiple diverse secret types found (excluding low-value)
            high_value_types = {t for t in secret_types_found.keys() if t not in low_value_types}
            if len(high_value_types) > 2:
                normalized_score += 0.1
            
            # Bonus for high confidence secrets
            if high_confidence_secrets > 0:
                normalized_score += min(0.15, high_confidence_secrets * 0.05)
            
            # Bonus for multiple scanner confirmation
            unique_scanners = len([s for s in scanner_base_weights.keys() 
                                 if s in self.leak_obj.secrets and 
                                 isinstance(self.leak_obj.secrets[s], constants.AutoVivification) and 
                                 len(self.leak_obj.secrets[s]) > 0])
            
            if unique_scanners > 2:
                normalized_score += 0.1
                
        else:
            normalized_score = 0.0

        # AI analysis boost (if available)
        ai_analysis = getattr(self.leak_obj, 'ai_analysis', None)
        if ai_analysis and ai_analysis.get('severity_assessment', {}).get('score', 0.0) > 0.5:
            normalized_score += ai_analysis.get('severity_assessment', {}).get('score', 0.0) * 0.1
            
        return min(round(normalized_score, 2), 1.0)
    
    def get_detailed_analysis(self) -> dict:
        """
        Return detailed analysis results for debugging and reporting.
        
        Returns:
            dict: Detailed breakdown of analysis scores and factors
        """
        profitability = self.calculate_profitability()
        
        # Collect secret statistics
        secret_stats = {
            "total_secrets": 0,
            "by_scanner": {},
            "by_type": {},
            "high_entropy_count": 0,
            "low_entropy_count": 0,
            "placeholder_count": 0,
        }
        
        for scanner_type in ["gitleaks", "gitsecrets", "trufflehog", "deepsecrets", "grepscan", "ioc_finder"]:
            if scanner_type in self.leak_obj.secrets and isinstance(self.leak_obj.secrets[scanner_type], constants.AutoVivification):
                scanner_secrets = self.leak_obj.secrets[scanner_type]
                secret_stats["by_scanner"][scanner_type] = len(scanner_secrets)
                secret_stats["total_secrets"] += len(scanner_secrets)
                
                for leak_id, leak_data in scanner_secrets.items():
                    secret_type, _ = self._classify_secret_type(leak_data)
                    secret_stats["by_type"][secret_type] = secret_stats["by_type"].get(secret_type, 0) + 1
                    
                    # Check entropy
                    secret_value = str(leak_data.get("Match", "") or leak_data.get("match", "") or "")
                    entropy = self.calculate_entropy(secret_value)
                    min_entropy = MIN_ENTROPY_THRESHOLDS.get(secret_type, 3.0)
                    
                    if entropy >= min_entropy:
                        secret_stats["high_entropy_count"] += 1
                    else:
                        secret_stats["low_entropy_count"] += 1
                    
                    if self.is_known_placeholder(secret_value):
                        secret_stats["placeholder_count"] += 1
        
        # Get corporate committers for analyst report (IMPORTANT!)
        corporate_committers = self.get_corporate_committers()
        target_company_committers = [c for c in corporate_committers if c.get("matches_company")]
        
        return {
            "profitability": profitability,
            "company_name": self.company_name,
            "company_tokens": self.company_tokens,
            "is_fork": self._is_repository_fork(),
            "secret_stats": secret_stats,
            "analysis_factors": {
                "dork_relevance": bool(self.leak_obj.dork and self.leak_obj.repo_name and 
                                      self.leak_obj.dork.lower() in self.leak_obj.repo_name.lower()),
                "corporate_email_found": len(corporate_committers) > 0,
                "target_company_email_found": len(target_company_committers) > 0,
                "high_popularity": self.leak_obj.stats.repo_stats_leak_stats_table.get('stargazers_count', 0) > 100,
            },
            # HIGHLIGHT FOR ANALYST: Corporate committers indicate high relevance!
            "corporate_committers": corporate_committers,
            "target_company_committers": target_company_committers,
            "repo_credibility": {
                "is_tiny": self._is_tiny_repository(),
                "is_small": self._is_small_repository(),
                "is_personal_project": self._is_likely_personal_project(),
                "is_highly_popular": self._is_highly_popular_repository(),
                "is_very_popular": self._is_very_popular_repository(),
                "all_public_emails": self._all_committers_use_public_email(),
                "has_corporate_committer": self._has_corporate_committer(),
                "has_target_company_committer": self.has_target_company_committer(),
                "credibility_score": self._calculate_repo_credibility_score(),
            }
        }

    def calculate_profitability(self) -> dict:
        org_relevance = self.calculate_organization_relevance_score()
        sensitive_data = self.calculate_sensitive_data_score()

        # Combine scores to get overall true positive chance
        # This is a simple weighted average; can be adjusted
        true_positive_chance = (org_relevance * 0.6) + (sensitive_data * 0.4)
        true_positive_chance = round(true_positive_chance, 2)

        # False positive chance is simply 1 - true_positive_chance
        false_positive_chance = round(1.0 - true_positive_chance, 2)

        return {
            "org_relevance": org_relevance,
            "sensitive_data": sensitive_data,
            "true_positive_chance": true_positive_chance,
            "false_positive_chance": false_positive_chance
        }

    def _get_message(self, key: str, lang: str = "ru", **kwargs) -> str:
        template = constants.LEAK_OBJ_MESSAGES.get(
            lang, constants.LEAK_OBJ_MESSAGES["en"]
        ).get(key, "")
        try:
            return template.format(**kwargs)
        except Exception:
            return template
    
    def get_final_assessment(self) -> str:
        """Generates a single, overall assessment for the analyst."""
        profitability = self.calculate_profitability()
        true_positive_chance = profitability["true_positive_chance"]
        lang = constants.LANGUAGE
        if true_positive_chance >= 0.8:
            return self._get_message("high_chance", lang)
        elif true_positive_chance >= 0.5:
            return self._get_message("medium_chance", lang)
        elif true_positive_chance >= 0.2:
            return self._get_message("low_chance", lang)
        else:
            return self._get_message("no_chance", lang)




