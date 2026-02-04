import re
import functools
from typing import Dict, Tuple, List, Set
from src.logger import logger
from src import constants
from src import Connector
from src import utils

from src.constants import (
    SECRET_CLASSIFICATION,
    KNOWN_PLACEHOLDER_PATTERNS,
    FRAMEWORK_CONFIG_PATTERNS,
    MIN_ENTROPY_THRESHOLDS,
    REPO_SIZE_TINY_KB,
    REPO_SIZE_SMALL_KB,
    REPO_MAX_STARS_FOR_PERSONAL,
    REPO_STARS_HIGH,
    REPO_STARS_VERY_HIGH,
    REPO_FORKS_HIGH,
    REPO_CONTRIBUTORS_HIGH,
)


class LeakAnalyzer:
    _compiled_patterns_cache: Dict[str, re.Pattern] = {}

    # Comment patterns for context analysis
    _COMMENT_PATTERN = re.compile(r"(#|//|/\*|\*/|<!--|-->|todo:|fixme:)\s*example", re.IGNORECASE)

    def __init__(self, leak_obj: any, bad_file_ext: bool = False):
        self.leak_obj = leak_obj
        self.bad_file_ext = bad_file_ext
        self.company_name = Connector.get_company_name(leak_obj.company_id)
        self.company_tokens = utils.generate_company_search_terms(self.company_name)
        self.relevance_breakdown: Dict[str, float] = {}

        # Context keywords that increase/decrease secret value
        self.context_keywords = {
            "critical": {
                "prod": 0.3,
                "production": 0.3,
                "live": 0.3,
                "database": 0.25,
                "db": 0.25,
                "mysql": 0.2,
                "postgres": 0.2,
                "admin": 0.2,
                "root": 0.2,
                "master": 0.2,
                "secret": 0.15,
                "private": 0.15,
                "confidential": 0.15,
                "aws": 0.25,
                "azure": 0.2,
                "gcp": 0.2,
                "cloud": 0.15,
                "payment": 0.3,
                "stripe": 0.25,
                "paypal": 0.25,
            },
            "negative": {
                "test": -0.3,
                "testing": -0.3,
                "unittest": -0.35,
                "dev": -0.2,
                "development": -0.2,
                "local": -0.15,
                "demo": -0.3,
                "example": -0.35,
                "sample": -0.35,
                "dummy": -0.4,
                "fake": -0.4,
                "mock": -0.35,
                "stub": -0.3,
                "template": -0.3,
                "boilerplate": -0.3,
                "skeleton": -0.25,
                "tutorial": -0.35,
                "guide": -0.3,
                "readme": -0.25,
                "sandbox": -0.3,
                "playground": -0.3,
                "fixture": -0.35,
                "spec": -0.3,
            },
        }

        # Corporate domain patterns will be generated dynamically (lazy initialization)
        self._corporate_domain_patterns = None

        # FILTER NEGATIVE KEYWORDS: If company name contains a negative keyword (e.g. "TestCorp"),
        # don't punish it for having "test" in context.
        if self.company_name:
            cn_lower = self.company_name.lower()
            negative_keywords = self.context_keywords["negative"]
            full_matches = [kw for kw in negative_keywords if kw in cn_lower]
            for kw in full_matches:
                del negative_keywords[kw]

    # Note: All validation helpers use utils module directly - no wrappers needed

    def _is_false_positive_path(self, file_path: str) -> bool:
        """Check if file path indicates likely false positive (delegates to utils)."""
        return utils.is_false_positive_path(file_path)

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

        entropy = utils.calculate_entropy(secret_value)
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
        if self._corporate_domain_patterns is None:
            self._corporate_domain_patterns = self._generate_corporate_domain_patterns()
        return self._corporate_domain_patterns

    @classmethod
    def _get_compiled_pattern(cls, pattern: str, flags: int = 0) -> re.Pattern:
        # Delegate to shared util to reuse cached regex compilation
        return utils.get_compiled_regex(pattern, flags)

    @classmethod
    def clear_pattern_cache(cls):
        """Clear cached compiled patterns."""
        cls._compiled_patterns_cache.clear()
        utils.clear_regex_cache()

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
                f"{token}corp",
                f"{token}group",
                f"{token}ltd",
                f"{token}inc",
                f"{token}bank",
                f"{token}tech",
                f"{token}dev",
                f"{token}it",
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
            if scanner_type in self.leak_obj.secrets and isinstance(
                self.leak_obj.secrets[scanner_type], constants.AutoVivification
            ):
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
            path_parts = re.split(r"[/\\.]", file_path)

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
                    f"{token}.*config",
                    f"{token}.*properties",
                    f"{token}.*credentials",
                    f"{token}.*auth",
                    f"{token}.*secret",
                    f"{token}.*key",
                ]
                if any(re.search(pattern, file_path) for pattern in critical_patterns):
                    score += 0.3

            if utils.is_binary_file(file_path):
                score -= 0.3
            elif self.bad_file_ext:
                score -= 0.5

        # Apply aggregate penalty if most paths are FP
        if len(file_paths) > 0 and fp_path_count / len(file_paths) > 0.5:
            score *= 0.5

        return max(0.0, min(score, 1.0))

    def _is_framework_config_path(self, file_path: str) -> bool:
        """Check if file path is framework config."""
        if not file_path:
            return False
        path_lower = file_path.lower()
        return any(f"/{fw}/" in path_lower or f"\\{fw}\\" in path_lower for fw in FRAMEWORK_CONFIG_PATTERNS)

    def _check_corporate_email_domains(self, email: str, company_tokens: list[str]) -> float:
        """Check if email belongs to corporate domain."""
        if not email or not company_tokens:
            return 0.0

        email_lower = email.lower()
        score = 0.0

        # Extract domain
        domain = utils.extract_domain_from_email(email_lower)
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
        if any(token in domain for token in company_tokens):
            score += 0.7

        # Penalty for common public domains
        if domain in constants.PUBLIC_EMAIL_DOMAINS:
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
        commits_count = self.leak_obj.stats.repo_stats_leak_stats_table.get("commits_count", 0)
        forks_count = self.leak_obj.stats.repo_stats_leak_stats_table.get("forks_count", 0)

        # If fork has many commits relative to popularity, it might have original content
        if commits_count > 100 and forks_count < 10:
            return 0.1  # Small penalty for active forks
        else:
            return 0.3  # Larger penalty for typical forks

    @functools.cached_property
    def _repo_stats(self) -> dict:
        """Cached repository statistics dictionary."""
        return self.leak_obj.stats.repo_stats_leak_stats_table or {}

    def _get_repo_stats(self) -> dict:
        """Get repository statistics dictionary (uses cached property)."""
        return self._repo_stats

    def _is_tiny_repository(self) -> bool:
        return self._repo_stats.get("size", 0) < REPO_SIZE_TINY_KB

    def _is_small_repository(self) -> bool:
        return self._repo_stats.get("size", 0) < REPO_SIZE_SMALL_KB

    def _is_likely_personal_project(self) -> bool:
        """Check if repository appears to be a personal/hobby project."""
        s = self._repo_stats
        return (
            sum(
                [
                    s.get("size", 0) < REPO_SIZE_SMALL_KB,
                    s.get("stargazers_count", 0) <= REPO_MAX_STARS_FOR_PERSONAL and s.get("forks_count", 0) <= 2,
                    s.get("contributors_count", 0) <= 1,
                ]
            )
            >= 2
        )

    def _is_highly_popular_repository(self) -> bool:
        s = self._repo_stats
        return (
            s.get("stargazers_count", 0) >= REPO_STARS_HIGH
            or s.get("forks_count", 0) >= REPO_FORKS_HIGH
            or s.get("contributors_count", 0) >= REPO_CONTRIBUTORS_HIGH
        )

    def _is_very_popular_repository(self) -> bool:
        return self._repo_stats.get("stargazers_count", 0) >= REPO_STARS_VERY_HIGH

    def get_committers_analysis(self) -> dict:
        """
        Analyze all committers in single pass for efficiency.

        Returns dict with:
            - all_use_public: bool - all committers use public emails
            - has_corporate: bool - at least one corporate email
            - corporate_list: List[dict] - corporate committers details
            - has_company_match: bool - at least one matches target company
        """
        committers = self.leak_obj.stats.commits_stats_commiters_table or []

        if not committers:
            return {"all_use_public": False, "has_corporate": False, "corporate_list": [], "has_company_match": False}

        corporate_list = []
        has_company_match = False
        company_tokens = self.company_tokens

        for committer in committers:
            email = committer.get("commiter_email", "")
            if email:
                domain = utils.extract_domain_from_email(email)
                if domain and domain not in constants.PUBLIC_EMAIL_DOMAINS:
                    # Check if domain matches company
                    matches_company = any(token in domain for token in company_tokens) if company_tokens else False

                    if matches_company:
                        has_company_match = True

                    corporate_list.append(
                        {
                            "commiter_name": committer.get("commiter_name", ""),
                            "commiter_email": email,
                            "domain": domain,
                            "matches_company": matches_company,
                        }
                    )

        return {
            "all_use_public": len(corporate_list) == 0,
            "has_corporate": len(corporate_list) > 0,
            "corporate_list": corporate_list,
            "has_company_match": has_company_match,
        }

    def _all_committers_use_public_email(self) -> bool:
        """Check if all committers use public email domains."""
        return self.get_committers_analysis()["all_use_public"]

    def _has_corporate_committer(self) -> bool:
        """Check if any committer uses a corporate email domain."""
        return self.get_committers_analysis()["has_corporate"]

    def get_corporate_committers(self) -> List[dict]:
        """Get list of committers with corporate (non-public) email domains."""
        return self.get_committers_analysis()["corporate_list"]

    def has_target_company_committer(self) -> bool:
        """Check if any committer has email from target company domain."""
        return self.get_committers_analysis()["has_company_match"]

    def _calculate_repo_credibility_score(self) -> float:
        """Calculate repository credibility score (0.0 to 1.0)."""
        score = 0.5  # Start neutral

        # Single analysis pass for all committer checks
        committer_analysis = self.get_committers_analysis()

        # Target company email - strongest signal
        if committer_analysis["has_company_match"]:
            score += 0.5  # Strong boost
        elif committer_analysis["has_corporate"]:
            score += 0.35  # Medium-high boost for generic corporate email
        elif committer_analysis["all_use_public"]:
            score -= 0.1  # Slight penalty for all public emails

        # Size/personal penalties (skip if any corporate committer)
        if not committer_analysis["has_corporate"]:
            if self._is_tiny_repository():
                score -= 0.1
            elif self._is_small_repository():
                score -= 0.05

            if self._is_likely_personal_project():
                score -= 0.15

        # Very popular = likely OSS with examples (slight penalty)
        if self._is_very_popular_repository():
            score -= 0.1
        elif self._is_highly_popular_repository():
            score -= 0.05

        # Fork penalty
        score -= self._calculate_fork_penalty()

        return max(0.0, min(1.0, score))

    def calculate_organization_relevance_score(self) -> float:
        self.relevance_breakdown = {}

        def add_signal(name: str, value: float):
            if value != 0:
                self.relevance_breakdown[name] = round(value, 3)
            return value

        score = 0.0
        dork = (self.leak_obj.dork or "").lower()
        repo_name_l = (self.leak_obj.repo_name or "").lower()
        stats_table = getattr(self.leak_obj.stats, "repo_stats_leak_stats_table", {}) or {}
        description = str(stats_table.get("description") or "")
        topics = str(stats_table.get("topics") or "")
        company_tokens = self.company_tokens

        if dork and repo_name_l and dork in repo_name_l:
            score += add_signal("dork_in_repo", 0.25)
        if dork and description and dork in description.lower():
            score += add_signal("dork_in_description", 0.15)

        if company_tokens and description:
            description_lower = description.lower()
            token_hits = sum(1 for token in company_tokens if token in description_lower)
            if token_hits:
                score += add_signal("company_tokens_description", min(0.16, 0.08 * token_hits))

        if self.leak_obj.author_name and dork and dork in self.leak_obj.author_name.lower():
            score += add_signal("dork_in_author", 0.25)

        committer_signals = 0.0
        committer_list = getattr(self.leak_obj.stats, "commits_stats_commiters_table", []) or []
        for committer in committer_list:
            committer_name = committer.get("commiter_name", "") or ""
            committer_email = committer.get("commiter_email", "") or ""
            committer_info = f"{committer_name} {committer_email}".lower()

            if dork and dork in committer_info:
                committer_signals += 0.05
            if company_tokens and any(tok in committer_info for tok in company_tokens):
                committer_signals += 0.1

            email_score = self._check_corporate_email_domains(committer_email, company_tokens)
            if email_score:
                committer_signals += min(0.4, email_score * 0.4)

        if committer_signals:
            score += add_signal("committers", min(committer_signals, 0.5))

        if company_tokens:
            if any(tok in repo_name_l for tok in company_tokens):
                score += add_signal("company_in_repo_name", 0.3)
            if description and any(tok in description.lower() for tok in company_tokens):
                score += add_signal("company_in_description", 0.1)
            if topics and any(tok in topics.lower() for tok in company_tokens):
                score += add_signal("company_in_topics", 0.05)

            file_path_score = self._analyze_file_paths_relevance(company_tokens)
            if file_path_score:
                score += add_signal("file_path_relevance", file_path_score * 0.35)

        if constants.COUNTRY_PROFILING:
            company_country = constants.COMPANY_COUNTRY_MAP.get(
                self.leak_obj.company_id, constants.COMPANY_COUNTRY_MAP_DEFAULT
            )

            if company_country == "ru":
                if re.search(r"[\u0400-\u04FF]", self.leak_obj.author_name or ""):
                    score += add_signal("ru_author", 0.05)
                if re.search(r"[\u0400-\u04FF]", description):
                    score += add_signal("ru_description", 0.05)
                for committer in committer_list:
                    if re.search(r"[\u0400-\u04FF]", committer.get("commiter_name", "")):
                        score += add_signal("ru_committer_name", 0.05)
                    if committer.get("commiter_email", "").lower().endswith(".ru"):
                        score += add_signal("ru_email", 0.05)
                    if re.search(r"@.+\.(com|org|net|io)$", committer.get("commiter_email", "").lower()):
                        score -= add_signal("non_ru_email_penalty", 0.02)
            elif company_country == "en":
                if re.fullmatch(r"[A-Za-z ._-]+", self.leak_obj.author_name or ""):
                    score += add_signal("en_author", 0.03)
                if re.fullmatch(r"[A-Za-z0-9 ,._-]+", description.strip()):
                    score += add_signal("en_description", 0.03)
                for committer in committer_list:
                    if re.fullmatch(r"[A-Za-z ._-]+", committer.get("commiter_name", "")):
                        score += add_signal("en_committer_name", 0.02)
                    if re.search(r"@.+\.(com|org|net|io)$", committer.get("commiter_email", "").lower()):
                        score += add_signal("en_email", 0.02)

        # Factor 5: Enhanced popularity penalty with fork analysis
        stars = stats_table.get("stargazers_count", 0)
        commiters = stats_table.get("commiters_count", 0)
        if stars > 100:
            score -= add_signal("popularity_penalty_medium", 0.1)
        if stars > 1000:
            score -= add_signal("popularity_penalty_high", 0.15)
        if commiters > 50:
            score -= add_signal("contributors_penalty", 0.05)
        if commiters > 200:
            score -= add_signal("contributors_penalty_high", 0.15)

        fork_penalty = self._calculate_fork_penalty()
        if fork_penalty:
            score -= add_signal("fork_penalty", fork_penalty)

        # Factor 6: AI assessment (if available and positive)
        ai_analysis = getattr(self.leak_obj, "ai_analysis", None)
        if ai_analysis and ai_analysis.get("company_relevance", {}).get("is_related"):
            ai_confidence = ai_analysis.get("company_relevance", {}).get("confidence", 0.0)
            score += add_signal("ai_positive", ai_confidence * 0.5 + 0.1)
        elif ai_analysis and not ai_analysis.get("company_relevance", {}).get("is_related"):
            ai_confidence = ai_analysis.get("company_relevance", {}).get("confidence", 0.0)
            score -= add_signal("ai_negative", ai_confidence * 0.3 + 0.05)

        # CRITICAL: Check for corporate committer with company domain match
        # This is the STRONGEST signal - should NOT be penalized by credibility
        has_target_company_committer = self.has_target_company_committer()

        if has_target_company_committer:
            # Corporate committer from target company = almost certain leak
            # Boost score significantly and prevent credibility from reducing it
            score = max(score, 0.75)  # Minimum 0.75 for any company domain match
            logger.debug(f"Corporate committer from target company found - boosting relevance score to {score}")

        # Blend with repository credibility to reduce false positives
        # But only apply heavy credibility penalty if NO corporate committer match
        credibility = self._calculate_repo_credibility_score()
        base_score = max(score, 0.0)

        if has_target_company_committer:
            # For corporate committers, credibility has less impact
            # Use lighter blending: 80% base score, 20% credibility influence
            blended = base_score * (0.8 + 0.2 * credibility)
        else:
            # For non-corporate sources, apply standard credibility blending
            blended = base_score * (0.7 + 0.3 * credibility)

        return min(round(blended, 2), 1.0)

    def get_relevance_breakdown(self) -> Dict[str, float]:
        """Return the last calculated relevance signal contributions."""
        return getattr(self, "relevance_breakdown", {})

    def _classify_secret_type(self, secret_data: dict) -> Tuple[str, float]:
        """Classify secret type and return criticality weight."""
        if not isinstance(secret_data, dict):
            return "unknown", 0.1

        # Get relevant fields from secret data
        rule_name = str(
            secret_data.get("RuleID", "") or secret_data.get("rule", "") or secret_data.get("Rule", "") or ""
        ).lower()
        match_text = str(
            secret_data.get("Match", "") or secret_data.get("match", "") or secret_data.get("Secret", "") or ""
        ).lower()
        file_path = str(
            secret_data.get("File", "") or secret_data.get("file", "") or secret_data.get("path", "") or ""
        ).lower()

        # Combine all text for analysis
        combined_text = f"{rule_name} {match_text} {file_path}"

        # Early false positive detection
        # Check for test/example indicators FIRST
        test_indicators = [
            "test_",
            "test-",
            "_test",
            "-test",
            "example_",
            "example-",
            "_example",
            "sample_",
            "sample-",
            "demo_",
            "demo-",
            "dummy_",
            "fake_",
            "mock_",
        ]

        for indicator in test_indicators:
            if indicator in combined_text:
                # Check if it's a test/dummy type
                if any(p in combined_text for p in ["password", "pass", "pwd", "secret", "key", "token"]):
                    return "dummy_password", 0.05

        # Check for common test file patterns
        test_path_patterns = [
            "/test/",
            "/tests/",
            "/spec/",
            "/example/",
            "/examples/",
            "/sample/",
            "/demo/",
            "/fixture/",
            "/mock/",
        ]
        if any(p in file_path for p in test_path_patterns):
            # Reduce weight for secrets in test paths
            weight_multiplier = 0.3
        else:
            weight_multiplier = 1.0

        # Type classification

        if "akia" in match_text or "aws_access" in combined_text or "aws_secret" in combined_text:
            return "aws_key", 0.95 * weight_multiplier

        if any(prefix in match_text for prefix in ["ghp_", "gho_", "ghu_", "ghs_"]):
            return "github_token", 0.95 * weight_multiplier

        if match_text.startswith("eyj") or "jwt" in rule_name:
            return "jwt_token", 0.8 * weight_multiplier

        for secret_type, (patterns, base_weight) in SECRET_CLASSIFICATION.items():
            if any(pattern in combined_text for pattern in patterns):
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
        file_path = str(
            secret_data.get("File", "") or secret_data.get("file", "") or secret_data.get("path", "") or ""
        ).lower()
        line_before = str(secret_data.get("LineBefore", "") or secret_data.get("line_before", "") or "").lower()
        line_after = str(secret_data.get("LineAfter", "") or secret_data.get("line_after", "") or "").lower()
        match_text = str(
            secret_data.get("Match", "") or secret_data.get("match", "") or secret_data.get("Secret", "") or ""
        ).lower()

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

        # Check for comment patterns
        if LeakAnalyzer._COMMENT_PATTERN.search(context):
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

        match_text = str(
            secret_data.get("Match", "") or secret_data.get("match", "") or secret_data.get("Secret", "") or ""
        )
        file_path = str(secret_data.get("File", "") or secret_data.get("file", "") or secret_data.get("path", "") or "")

        validation_score = 0.5
        total_penalty = 0.0

        # Binary file check
        if utils.is_binary_file(file_path):
            total_penalty += 0.6

        # Known documentation example
        if utils.is_known_example_secret(match_text):
            total_penalty += 0.5

        # Placeholder check
        if utils.is_known_placeholder(match_text):
            total_penalty += 0.5

        # Template config file
        if utils.is_template_config_file(file_path):
            total_penalty += 0.3

        # Mock/fixture data path
        if utils.is_mock_data_path(file_path):
            total_penalty += 0.25

        # Local host check
        if utils.contains_local_host(match_text):
            total_penalty += 0.2

        # Random string with keyword
        if utils.is_random_string_with_keyword(match_text, self.company_tokens):
            total_penalty += 0.5

        # Encoded data check
        if not utils.has_meaningful_structure(match_text) and utils.looks_like_encoded_data(match_text):
            total_penalty += 0.3

        # Repetitive pattern
        if utils.has_repetitive_pattern(match_text):
            total_penalty += 0.3

        # Entropy analysis
        entropy_score = self._calculate_secret_entropy_score(match_text, secret_type)

        # Format validation by type
        type_validation_score = self._validate_by_secret_type(match_text, secret_type)

        # File path context
        if self._is_false_positive_path(file_path):
            total_penalty += 0.2

        # Meaningful structure bonus
        structure_bonus = 0.0
        if utils.has_meaningful_structure(match_text):
            structure_bonus = 0.2

        # Repository credibility
        repo_credibility = self._calculate_repo_credibility_score()

        # Combine scores
        base_score = (
            entropy_score * 0.35
            + type_validation_score * 0.35
            + repo_credibility * 0.20
            + validation_score * 0.10
            + structure_bonus
        )

        penalty_factor = max(0.3, 1.0 - min(total_penalty, 0.7))
        validation_score = base_score * penalty_factor

        # Additional checks
        match_lower = match_text.lower()

        # Check for test/example patterns in secret value (not file path/repo)
        fp_value_patterns = [
            "example",
            "dummy",
            "fake",
            "sample",
            "placeholder",
            "changeme",
            "change_me",
            "your_",
            "xxxx",
        ]
        pattern_matches = sum(1 for p in fp_value_patterns if p in match_lower)
        if pattern_matches > 0:
            validation_score *= max(0.2, 1.0 - pattern_matches * 0.2)

        # Check for very short or very simple values
        if len(match_text) < 6:
            validation_score *= 0.3
        elif len(match_text) < 10 and match_text.isalnum():
            validation_score *= 0.6

        # Check for all same characters
        if len(set(match_text)) <= 2 and len(match_text) > 3:
            validation_score *= 0.1

        # Long random string penalty
        if len(match_text) > 50 and not utils.has_meaningful_structure(match_text):
            upper_ratio = sum(1 for c in match_text if c.isupper()) / len(match_text)
            lower_ratio = sum(1 for c in match_text if c.islower()) / len(match_text)
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

        if secret_type == "private_key":  # pragma: allowlist secret
            if "-----BEGIN" in match_text and "-----END" in match_text:
                score = 0.95
            elif len(match_text) > 200:
                score = 0.7
            else:
                score = 0.3

        elif secret_type == "aws_key":  # pragma: allowlist secret
            if re.match(r"^AKIA[A-Z0-9]{16}$", match_text):
                score = 0.95
            elif len(match_text) == 40 and re.match(r"^[A-Za-z0-9+/]+$", match_text):
                score = 0.85
            else:
                score = 0.4

        elif secret_type == "github_token":  # pragma: allowlist secret
            if re.match(r"^gh[pous]_[A-Za-z0-9]{36,}$", match_text):
                score = 0.95
            elif match_text.startswith(("ghp_", "gho_", "ghu_", "ghs_")):
                score = 0.8
            else:
                score = 0.3

        elif secret_type == "jwt_token":  # pragma: allowlist secret
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

        elif secret_type == "password":  # pragma: allowlist secret
            # Passwords should have some complexity
            fake_passwords = {
                "password",
                "123456",
                "admin",
                "root",
                "test",
                "guest",
                "demo",
                "sample",
                "example",
                "default",
                "user",
                "pass",
                "password1",
                "password123",
                "admin123",
                "root123",
                "test123",
                "qwerty",
                "abc123",
                "letmein",
                "welcome",
                "monkey",
                "master",
            }
            if match_lower in fake_passwords:
                score = 0.05
            elif len(match_text) < 6:
                score = 0.15
            elif (
                len(match_text) >= 12 and any(c.isupper() for c in match_text) and any(c.isdigit() for c in match_text)
            ):
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

        elif secret_type == "certificate":  # pragma: allowlist secret
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
            "trufflehog": 0.9,  # Highest confidence
            "gitleaks": 0.8,  # High confidence
            "deepsecrets": 0.75,  # High confidence
            "gitsecrets": 0.6,  # Medium confidence
            "ioc_finder": 0.5,  # Medium confidence for IOCs
            "grepscan": 0.3,  # Lower confidence, depends on dork
        }

        for scanner_type, base_weight in scanner_base_weights.items():
            if scanner_type in self.leak_obj.secrets and isinstance(
                self.leak_obj.secrets[scanner_type], constants.AutoVivification
            ):
                scanner_secrets = self.leak_obj.secrets[scanner_type]

                for leak_id, leak_data in scanner_secrets.items():
                    total_leaks += 1

                    # Classify secret type and get its weight
                    secret_type, type_weight = self._classify_secret_type(leak_data)
                    secret_types_found[secret_type] = secret_types_found.get(secret_type, 0) + 1

                    # Get secret value for deduplication and analysis
                    secret_value = str(
                        leak_data.get("Match", "") or leak_data.get("match", "") or leak_data.get("Secret", "") or ""
                    )
                    file_path = str(
                        leak_data.get("File", "") or leak_data.get("file", "") or leak_data.get("path", "") or ""
                    )

                    # Skip duplicates (same secret found by multiple scanners)
                    value_hash = hash(secret_value[:100] if len(secret_value) > 100 else secret_value)
                    if value_hash in secret_values_seen:
                        continue
                    secret_values_seen.add(value_hash)

                    # False positive detection (lightweight, main logic in _validate_secret_format)

                    # Only hard-skip for binary files (definitely not source code)
                    if utils.is_binary_file(file_path):
                        false_positive_count += 1
                        continue

                    # Check for repetitive patterns - reduce weight but don't skip
                    if utils.has_repetitive_pattern(secret_value):
                        type_weight *= 0.3

                    # Basic entropy check - only skip if VERY low
                    entropy = utils.calculate_entropy(secret_value)
                    min_entropy = MIN_ENTROPY_THRESHOLDS.get(secret_type, MIN_ENTROPY_THRESHOLDS["default"])

                    if entropy < min_entropy * 0.5:
                        # Very low entropy - almost certainly fake
                        false_positive_count += 1
                        continue
                    elif entropy < min_entropy:
                        # Low entropy - reduce weight
                        type_weight *= 0.4

                    # Analyze context around the secret
                    context_score = self._analyze_secret_context(leak_data)

                    # Validate secret format (comprehensive FP detection with penalties)
                    validation_score = self._validate_secret_format(leak_data, secret_type)

                    if validation_score < 0.10:
                        false_positive_count += 1
                        continue

                    # Calculate final score for this secret
                    secret_score = base_weight * type_weight * validation_score

                    secret_score += context_score * 0.3
                    secret_score = max(0.0, secret_score)

                    # Track high confidence secrets
                    if secret_score > 0.5:
                        high_confidence_secrets += 1

                    total_score += secret_score

        # Aggregate false positive analysis

        actual_secrets = total_leaks - false_positive_count
        if total_leaks > 0:
            fp_ratio = false_positive_count / total_leaks
            if fp_ratio > 0.8:
                total_score *= 0.3
            elif fp_ratio > 0.5:
                total_score *= 0.6

        low_value_types = {"test_password", "dev_password", "dummy_password"}
        if secret_types_found and all(t in low_value_types for t in secret_types_found):
            total_score *= 0.2

        # Normalize score

        if actual_secrets > 0:
            # Improved normalization: give higher scores for real secrets
            # Old formula was too aggressive: total_score / (total_score + log(n) * 5)
            # New formula: diminishing returns but preserves high scores better
            base_normalized = min(total_score / 3.0, 1.0)  # Normalize to 0-1 range

            # Bonus for multiple diverse secret types found (excluding low-value)
            high_value_types = {t for t in secret_types_found.keys() if t not in low_value_types}
            if len(high_value_types) > 2:
                base_normalized += 0.1
            elif len(high_value_types) >= 1:
                base_normalized += 0.05  # Even 1 high-value type gets bonus

            # Bonus for high confidence secrets
            if high_confidence_secrets > 0:
                base_normalized += min(0.2, high_confidence_secrets * 0.07)

            # Bonus for multiple scanner confirmation
            unique_scanners = len(
                [
                    s
                    for s in scanner_base_weights.keys()
                    if s in self.leak_obj.secrets
                    and isinstance(self.leak_obj.secrets[s], constants.AutoVivification)
                    and len(self.leak_obj.secrets[s]) > 0
                ]
            )

            if unique_scanners > 2:
                base_normalized += 0.15
            elif unique_scanners >= 2:
                base_normalized += 0.08

            # Bonus for having actual secrets (not all filtered as FP)
            if actual_secrets >= 1:
                base_normalized += 0.1
            if actual_secrets >= 3:
                base_normalized += 0.1

            normalized_score = base_normalized
        else:
            normalized_score = 0.0

        # AI analysis boost (if available)
        ai_analysis = getattr(self.leak_obj, "ai_analysis", None)
        if ai_analysis and ai_analysis.get("severity_assessment", {}).get("score", 0.0) > 0.5:
            normalized_score += ai_analysis.get("severity_assessment", {}).get("score", 0.0) * 0.1

        # CRITICAL: Corporate committer boost for sensitive data score
        # If we have corporate committers, secrets are more likely real
        if self.has_target_company_committer():
            normalized_score = max(normalized_score, 0.5)  # Minimum 0.5 for target company
            normalized_score += 0.15
        elif self._has_corporate_committer():
            normalized_score = max(normalized_score, 0.35)  # Minimum 0.35 for any corporate
            normalized_score += 0.1

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
            if scanner_type in self.leak_obj.secrets and isinstance(
                self.leak_obj.secrets[scanner_type], constants.AutoVivification
            ):
                scanner_secrets = self.leak_obj.secrets[scanner_type]
                secret_stats["by_scanner"][scanner_type] = len(scanner_secrets)
                secret_stats["total_secrets"] += len(scanner_secrets)

                for leak_id, leak_data in scanner_secrets.items():
                    secret_type, _ = self._classify_secret_type(leak_data)
                    secret_stats["by_type"][secret_type] = secret_stats["by_type"].get(secret_type, 0) + 1

                    # Check entropy
                    secret_value = str(leak_data.get("Match", "") or leak_data.get("match", "") or "")
                    entropy = utils.calculate_entropy(secret_value)
                    min_entropy = MIN_ENTROPY_THRESHOLDS.get(secret_type, 3.0)

                    if entropy >= min_entropy:
                        secret_stats["high_entropy_count"] += 1
                    else:
                        secret_stats["low_entropy_count"] += 1

                    if utils.is_known_placeholder(secret_value):
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
                "dork_relevance": bool(
                    self.leak_obj.dork
                    and self.leak_obj.repo_name
                    and self.leak_obj.dork.lower() in self.leak_obj.repo_name.lower()
                ),
                "corporate_email_found": bool(corporate_committers),
                "target_company_email_found": bool(target_company_committers),
                "high_popularity": self.leak_obj.stats.repo_stats_leak_stats_table.get("stargazers_count", 0) > 100,
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
            },
        }

    def calculate_profitability(self) -> dict:
        """Calculate overall profitability score combining organization relevance and sensitive data."""
        org_relevance = self.calculate_organization_relevance_score()
        sensitive_data = self.calculate_sensitive_data_score()

        # Count actual secrets found by scanners
        secrets_count = 0
        scanners = ["gitleaks", "gitsecrets", "trufflehog", "grepscan", "deepsecrets"]
        for scanner in scanners:
            if scanner in self.leak_obj.secrets and isinstance(
                self.leak_obj.secrets[scanner], constants.AutoVivification
            ):
                secrets_count += len(self.leak_obj.secrets[scanner])

        # Combine scores to get overall true positive chance
        # Base formula: weighted average of org_relevance and sensitive_data
        true_positive_chance = (org_relevance * 0.5) + (sensitive_data * 0.5)

        # CRITICAL: If secrets were actually found, ensure minimum score
        # This prevents real leaks from being marked as false positives
        if secrets_count > 0:
            # Minimum 0.35 if any secrets found
            true_positive_chance = max(true_positive_chance, 0.35)

            # Bonus based on number of secrets (diminishing returns)
            if secrets_count >= 5:
                true_positive_chance = max(true_positive_chance, 0.5)
            if secrets_count >= 10:
                true_positive_chance = max(true_positive_chance, 0.6)

        # If sensitive_data score is high, it should pull up the total
        # Even without org_relevance, high-confidence secrets matter
        if sensitive_data >= 0.7:
            true_positive_chance = max(true_positive_chance, 0.55)
        elif sensitive_data >= 0.5:
            true_positive_chance = max(true_positive_chance, 0.4)

        # Corporate committer guarantees high score
        if self.has_target_company_committer():
            true_positive_chance = max(true_positive_chance, 0.8)
        elif self._has_corporate_committer():
            true_positive_chance = max(true_positive_chance, 0.6)

        true_positive_chance = round(min(true_positive_chance, 1.0), 2)

        # False positive chance is simply 1 - true_positive_chance
        false_positive_chance = round(1.0 - true_positive_chance, 2)

        return {
            "org_relevance": org_relevance,
            "sensitive_data": sensitive_data,
            "true_positive_chance": true_positive_chance,
            "false_positive_chance": false_positive_chance,
        }

    def _get_message(self, key: str, lang: str = "ru", **kwargs) -> str:
        template = constants.LEAK_OBJ_MESSAGES.get(lang, constants.LEAK_OBJ_MESSAGES["en"]).get(key, "")
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
