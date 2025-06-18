import re
from src.logger import logger
from src import constants

class LeakAnalyzer: 
    '''
        Class to analyze the profitability of a leak based on organization relevance and sensitive data presence
    '''
    def __init__(self, leak_obj: any):
        self.leak_obj = leak_obj

    def calculate_organization_relevance_score(self) -> float:
        score = 0.0

        # Factor 1: Dork relevance
        # If the dork is found in the repo name or description, it's highly relevant
        if self.leak_obj.dork and self.leak_obj.repo_name and self.leak_obj.dork.lower() in self.leak_obj.repo_name.lower():
            score += 0.3
        if self.leak_obj.dork and self.leak_obj.stats.repo_stats_leak_stats_table.get("description") and \
           self.leak_obj.dork.lower() in self.leak_obj.stats.repo_stats_leak_stats_table["description"].lower():
            score += 0.2

        # Factor 2: Author/Committer relevance
        # Check if author or committers names/emails contain parts of the dork or company name
        if self.leak_obj.author_name and self.leak_obj.dork and self.leak_obj.dork.lower() in self.leak_obj.author_name.lower():
            score += 0.2
        
        # Check committers
        for committer in self.leak_obj.stats.commits_stats_commiters_table:
            committer_info = f'{committer.get("commiter_name", "")} {committer.get("commiter_email", "")}'
            if self.leak_obj.dork and self.leak_obj.dork.lower() in committer_info.lower():
                score += 0.1 # Each relevant committer adds a small score

        # Factor 3: AI assessment (if available and positive)
        if self.leak_obj.stats.ai_result == 1: # Assuming 1 means AI believes it's related
            score += 0.2

        # Cap the score at 1.0
        return min(score, 1.0)

    def calculate_sensitive_data_score(self) -> float:
        score = 0.0
        total_leaks = 0
        sensitive_leak_types = {
            "gitleaks": 0.25,  # High confidence in gitleaks findings
            "gitsecrets": 0.2, # Medium confidence
            "trufflehog": 0.3, # High confidence
            "deepsecrets": 0.25, # High confidence
            "grepscan": 0.1,   # Lower confidence, depends on dork
            "ioc_finder": 0.15 # Medium confidence for IOCs
        }

        for scanner_type, weight in sensitive_leak_types.items():
            if scanner_type in self.leak_obj.secrets and isinstance(self.leak_obj.secrets[scanner_type], constants.AutoVivification):
                num_leaks = len(self.leak_obj.secrets[scanner_type])
                total_leaks += num_leaks
                score += num_leaks * weight
        
        # Normalize score based on total leaks or apply a threshold
        if total_leaks > 0:
            # Simple normalization, could be more complex (e.g., logarithmic)
            score = min(score / total_leaks, 1.0) if total_leaks > 0 else 0.0

        # Factor: AI assessment for sensitive data (if AI can specifically assess this)
        # Currently, AIObj.ai_result is a general relevance. If AI can provide a specific sensitive data score, use it.
        # For now, we'll assume a positive general AI result slightly boosts this score.
        if self.leak_obj.stats.ai_result == 1:
            score += 0.1 # Small boost if AI thinks it's generally relevant

        return min(score, 1.0)

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


