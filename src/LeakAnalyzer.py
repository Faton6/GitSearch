import re
import math
from src.logger import logger
from src import constants
from src import Connector
from src import utils
from src.AIObj import AIObj # Import the new AIObj

class LeakAnalyzer: 
    """
        Class to analyze the profitability of a leak based on organization relevance and sensitive data presence
    """
    def __init__(self, leak_obj: any):
        self.leak_obj = leak_obj
        self.company_name = Connector.get_company_name(leak_obj.company_id)
        self.company_tokens = utils.generate_company_search_terms(self.company_name)
        
        # Mapping for secret types and their criticality weights
        self.secret_type_weights = {
            # Critical secrets (private keys, certificates)
            "private_key": 1.0,
            "rsa_private_key": 1.0,
            "ssh_private_key": 1.0,
            "certificate": 0.9,
            "pkcs8": 0.9,
            
            # High-value secrets (production credentials)
            "database_password": 0.8,
            "prod_password": 0.8,
            "admin_password": 0.8,
            "api_key": 0.7,
            "access_token": 0.7,
            "secret_key": 0.7,
            "auth_token": 0.7,
            
            # Medium-value secrets
            "password": 0.5,
            "token": 0.5,
            "key": 0.4,
            "credential": 0.4,
            
            # Low-value secrets (likely test/dev)
            "test_password": 0.1,
            "dev_password": 0.1,
            "dummy_password": 0.1,
            "example_key": 0.1,
            "sample_token": 0.1,
        }
        
        # Context keywords that increase/decrease secret value
        self.context_keywords = {
            "critical": {
                "prod": 0.3, "production": 0.3, "live": 0.3,
                "database": 0.25, "db": 0.25,
                "admin": 0.2, "root": 0.2, "master": 0.2,
                "secret": 0.15, "private": 0.15, "confidential": 0.15
            },
            "negative": {
                "test": -0.2, "testing": -0.2,
                "dev": -0.15, "development": -0.15,
                "demo": -0.2, "example": -0.25, "sample": -0.25,
                "dummy": -0.3, "fake": -0.3, "mock": -0.25
            }
        }
        
        # Corporate domain patterns will be generated dynamically
        self.corporate_domain_patterns = self._generate_corporate_domain_patterns()
    

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
        """Analyze file paths for company relevance."""
        file_paths = self._extract_file_paths_from_secrets()
        if not file_paths or not company_tokens:
            return 0.0
            
        score = 0.0
        
        for file_path in file_paths:
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
        
        return min(score, 1.0)
    
    def _extract_domain_from_email(self, email: str) -> str:
        """Extract domain from email address."""
        if not email or '@' not in email:
            return ""
        
        try:
            domain = email.split('@')[-1].lower().strip()
            return domain
        except:
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
        
        # Check against known corporate domains
        for company, patterns in self.corporate_domain_patterns.items():
            if any(token in company for token in company_tokens):
                for pattern in patterns:
                    if re.search(pattern, domain):
                        return 1.0  # Perfect match for corporate domain
        
        # Check for company tokens in domain
        for token in company_tokens:
            if token in domain:
                score += 0.7
        
        # Penalty for common public domains
        public_domains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "mail.ru", "yandex.ru"]
        if any(pub_domain in domain for pub_domains in public_domains):
            score -= 0.3
            
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
                if re.search(r"[А-Яа-я]", self.leak_obj.author_name or ""):
                    score += 0.05
                if re.search(r"[А-Яа-я]", description):
                    score += 0.05
                for committer in self.leak_obj.stats.commits_stats_commiters_table:
                    if re.search(r"[А-Яа-я]", committer.get('commiter_name', '')):
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
        # This will now use the comprehensive AI analysis from AIObj
        if self.leak_obj.ai_analysis and self.leak_obj.ai_analysis.get('company_relevance', {}).get('is_related'):
            score += self.leak_obj.ai_analysis.get('company_relevance', {}).get('confidence', 0.0) * 0.3 # Boost based on AI confidence
        elif self.leak_obj.ai_analysis and not self.leak_obj.ai_analysis.get('company_relevance', {}).get('is_related'):
            score -= self.leak_obj.ai_analysis.get('company_relevance', {}).get('confidence', 0.0) * 0.3 # Penalty based on AI confidence

        # Cap the score at 1.0
        score = max(score, 0.0)  # Ensure score is not negative
        score = round(score, 2)  # Round to 2 decimal places for consistency
        return min(score, 1.0)

    def _classify_secret_type(self, secret_data: dict) -> tuple[str, float]:
        """Classify the type of secret and return its criticality weight."""
        if not isinstance(secret_data, dict):
            return "unknown", 0.1
            
        # Get relevant fields from secret data
        rule_name = str(secret_data.get("RuleID", "") or secret_data.get("rule", "") or "").lower()
        match_text = str(secret_data.get("Match", "") or secret_data.get("match", "") or secret_data.get("Secret", "") or "").lower()
        file_path = str(secret_data.get("File", "") or secret_data.get("file", "") or "").lower()
        
        # Combine all text for analysis
        combined_text = f"{rule_name} {match_text} {file_path}"
        
        # Check for specific secret patterns
        if any(pattern in combined_text for pattern in ["private_key", "private-key", "rsa private", "ssh-rsa", "-----begin"]):
            return "private_key", 1.0
        elif any(pattern in combined_text for pattern in ["certificate", "cert", "pkcs", "x509"]):
            return "certificate", 0.9
        elif any(pattern in combined_text for pattern in ["database_password", "db_password", "database_pass"]):
            return "database_password", 0.8
        elif any(pattern in combined_text for pattern in ["prod_password", "production_password", "prod_pass"]):
            return "prod_password", 0.8
        elif any(pattern in combined_text for pattern in ["admin_password", "admin_pass", "root_password"]):
            return "admin_password", 0.8
        elif any(pattern in combined_text for pattern in ["api_key", "api-key", "apikey"]):
            return "api_key", 0.7
        elif any(pattern in combined_text for pattern in ["access_token", "access-token", "bearer"]):
            return "access_token", 0.7
        elif any(pattern in combined_text for pattern in ["secret_key", "secret-key", "secretkey"]):
            return "secret_key", 0.7
        elif any(pattern in combined_text for pattern in ["auth_token", "auth-token", "authtoken"]):
            return "auth_token", 0.7
        elif any(pattern in combined_text for pattern in ["test_password", "test_pass", "testing_pass"]):
            return "test_password", 0.1
        elif any(pattern in combined_text for pattern in ["dev_password", "dev_pass", "development_pass"]):
            return "dev_password", 0.1
        elif any(pattern in combined_text for pattern in ["dummy", "example", "sample", "fake"]):
            return "dummy_password", 0.1
        elif any(pattern in combined_text for pattern in ["password", "pass"]):
            return "password", 0.5
        elif any(pattern in combined_text for pattern in ["token"]):
            return "token", 0.5
        elif any(pattern in combined_text for pattern in ["key"]):
            return "key", 0.4
        else:
            return "unknown", 0.3
    
    def _analyze_secret_context(self, secret_data: dict) -> float:
        """Analyze the context around a secret to determine its criticality."""
        if not isinstance(secret_data, dict):
            return 0.0
            
        context_score = 0.0
        
        # Get context fields
        file_path = str(secret_data.get("File", "") or secret_data.get("file", "") or "").lower()
        line_before = str(secret_data.get("LineBefore", "") or "").lower()
        line_after = str(secret_data.get("LineAfter", "") or "").lower()
        match_text = str(secret_data.get("Match", "") or secret_data.get("match", "") or "").lower()
        
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
        
        # File path analysis
        if any(path in file_path for path in ["config", "properties", "env", "secret"]):
            context_score += 0.2
        if any(path in file_path for path in ["test", "spec", "example", "demo"]):
            context_score -= 0.2
        
        return context_score
    
    def _validate_secret_format(self, secret_data: dict, secret_type: str) -> float:
        """Validate secret format to determine if it's likely real or fake."""
        if not isinstance(secret_data, dict):
            return 0.5
            
        match_text = str(secret_data.get("Match", "") or secret_data.get("match", "") or secret_data.get("Secret", "") or "")
        
        # Basic validation based on secret type
        validation_score = 0.5  # Default neutral score
        
        if secret_type == "private_key":
            if "-----BEGIN" in match_text and "-----END" in match_text:
                validation_score = 0.9
            elif len(match_text) > 100:  # Reasonable length for keys
                validation_score = 0.7
        
        elif secret_type in ["api_key", "access_token", "secret_key"]:
            # Check for realistic length and complexity
            if len(match_text) >= 16 and any(c.isdigit() for c in match_text) and any(c.isalpha() for c in match_text):
                validation_score = 0.8
            elif len(match_text) < 8:
                validation_score = 0.2  # Too short to be real
        
        elif secret_type == "password":
            # Check for common fake passwords
            fake_passwords = ["password", "123456", "admin", "test", "example", "dummy", "fake"]
            if match_text.lower() in fake_passwords:
                validation_score = 0.1
            elif len(match_text) >= 8:
                validation_score = 0.6
        
        # Check for obvious test/example patterns
        if any(pattern in match_text.lower() for pattern in ["test", "example", "dummy", "fake", "sample"]):
            validation_score *= 0.3
            
        return validation_score

    def calculate_sensitive_data_score(self) -> float:
        """Enhanced calculation of sensitive data score with detailed secret classification."""
        total_score = 0.0
        total_leaks = 0
        
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
                    
                    # Analyze context around the secret
                    context_score = self._analyze_secret_context(leak_data)
                    
                    # Validate secret format
                    validation_score = self._validate_secret_format(leak_data, secret_type)
                    
                    # Calculate final score for this secret
                    secret_score = base_weight * type_weight * validation_score
                    
                    # Apply context modifiers
                    secret_score += context_score
                    secret_score = max(0.0, secret_score)  # Ensure non-negative
                    
                    total_score += secret_score
        
        # Normalize score with improved formula
        if total_leaks > 0:
            # Use logarithmic scaling for diminishing returns
            normalized_score = total_score / (total_score + math.log(total_leaks + 1) * 5)
            
            # Bonus for multiple diverse secret types found
            unique_scanners = len([s for s in scanner_base_weights.keys() 
                                 if s in self.leak_obj.secrets and 
                                 isinstance(self.leak_obj.secrets[s], constants.AutoVivification) and 
                                 len(self.leak_obj.secrets[s]) > 0])
            
            if unique_scanners > 2:
                normalized_score += 0.1  # Bonus for multiple scanner confirmation
                
        else:
            normalized_score = 0.0

        # AI assessment boost for sensitive data (if AI can specifically assess this)
        if self.leak_obj.ai_analysis and self.leak_obj.ai_analysis.get('severity_assessment', {}).get('score', 0.0) > 0.5:
            normalized_score += self.leak_obj.ai_analysis.get('severity_assessment', {}).get('score', 0.0) * 0.1 # Small boost if AI thinks it's generally relevant

        return min(round(normalized_score, 2), 1.0)

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

    def get_final_assessment(self) -> str:
        """Generates a single, overall assessment for the analyst."""
        profitability = self.calculate_profitability()
        true_positive_chance = profitability["true_positive_chance"]
        lang = constants.LANGUAGE
        if true_positive_chance >= 0.8:
            return self.status.append(self._get_message("high_chance", lang))
        elif true_positive_chance >= 0.5:
            return self.status.append(self._get_message("medium_chance", lang))
        elif true_positive_chance >= 0.2:
            return self.status.append(self._get_message("low_chance", lang))
        else:
            return self.status.append(self._get_message("no_chance", lang))




