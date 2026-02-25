"""
GitHub GraphQL API Client for optimized queries.

This module provides GraphQL queries that fetch repository data and statistics
in a single request, reducing the number of API calls needed.

IMPORTANT: Personal Access Tokens must have 'repo' or 'public_repo' scope
to access GraphQL API. If tokens lack these scopes, the client automatically
falls back to REST API without generating excessive error messages.
"""

import requests
import time
from typing import Dict, List, Any, Optional
from src.logger import logger
from src import constants


class GitHubGraphQLClient:
    """Client for GitHub GraphQL API with optimized queries."""

    GRAPHQL_ENDPOINT = "https://api.github.com/graphql"

    _graphql_disabled = False
    _tokens_without_graphql = set()
    _tokens_with_graphql = set()

    # Base repository fields (shared between full and limited queries)
    _REPO_BASE_FIELDS = """
            name
            owner { login }
            url
            isPrivate
            createdAt
            updatedAt
            pushedAt
            description
            stargazerCount
            forkCount
            watchers { totalCount }
            issues(states: OPEN) { totalCount }
            hasIssuesEnabled
            hasProjectsEnabled
            hasWikiEnabled
            diskUsage
            primaryLanguage { name }
            languages(first: 5) { edges { size node { name } } }
            repositoryTopics(first: 5) { nodes { topic { name } } }
            defaultBranchRef { target { ... on Commit { history(first: 1) { totalCount } } } }
    """

    # Full query with collaborators (requires push access)
    SEARCH_REPOS_WITH_STATS = f"""
    query SearchReposWithStats($query: String!, $first: Int!, $after: String) {{
      search(query: $query, type: REPOSITORY, first: $first, after: $after) {{
        repositoryCount
        pageInfo {{ hasNextPage endCursor }}
        nodes {{ ... on Repository {{ {_REPO_BASE_FIELDS} collaborators {{ totalCount }} }} }}
      }}
      rateLimit {{ limit remaining resetAt cost }}
    }}
    """

    # Limited query without collaborators
    SEARCH_REPOS_WITH_STATS_LIMITED = f"""
    query SearchReposWithStats($query: String!, $first: Int!, $after: String) {{
      search(query: $query, type: REPOSITORY, first: $first, after: $after) {{
        repositoryCount
        pageInfo {{ hasNextPage endCursor }}
        nodes {{ ... on Repository {{ {_REPO_BASE_FIELDS} }} }}
      }}
      rateLimit {{ limit remaining resetAt cost }}
    }}
    """

    # Search code with context
    SEARCH_CODE_WITH_CONTEXT = """
    query SearchCodeWithContext($query: String!, $first: Int!, $after: String) {
      search(query: $query, type: CODE, first: $first, after: $after) {
        codeCount
        pageInfo { hasNextPage endCursor }
        nodes {
          ... on Blob {
            repository {
              name
              owner { login }
              url
              isPrivate
              createdAt
              updatedAt
              stargazerCount
              forkCount
              diskUsage
              description
            }
            path
            text
          }
        }
      }
      rateLimit { limit remaining resetAt cost }
    }
    """

    def __init__(self):
        """Initialize GraphQL client with HTTP session pooling."""
        self.use_limited_queries = False  # Flag to use queries without special permissions
        self._session = None

    def _get_session(self) -> requests.Session:
        """Get or create HTTP session with connection pooling."""
        if self._session is None:
            self._session = requests.Session()
            # Configure connection pool for GraphQL endpoint
            adapter = requests.adapters.HTTPAdapter(
                pool_connections=5,
                pool_maxsize=10,
                max_retries=requests.adapters.Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504]),
            )
            self._session.mount("https://", adapter)
        return self._session

    def _get_token(self) -> Optional[str]:
        try:
            from src.github_rate_limiter import get_rate_limiter

            rate_limiter = get_rate_limiter()

            # Get best available token from rate limiter
            token = rate_limiter.get_best_token()

            # Skip tokens known to lack GraphQL access
            if token and token in self._tokens_without_graphql:
                all_tokens = constants.GITHUB_TOKENS if hasattr(constants, "GITHUB_TOKENS") else []
                for alt_token in all_tokens:
                    if alt_token not in self._tokens_without_graphql and alt_token != token:
                        logger.debug("Skipping token without GraphQL access, trying alternative")
                        return alt_token

            return token
        except (RuntimeError, ImportError):
            return next(constants.token_generator())

    def _update_rate_limit(self, token: str, rate_limit_data: Dict):
        """Update rate limit from GraphQL response."""
        try:
            from src.github_rate_limiter import get_rate_limiter

            rate_limiter = get_rate_limiter()

            # Convert GraphQL rate limit to REST format for compatibility
            headers = {
                "X-RateLimit-Limit": str(rate_limit_data.get("limit", 5000)),
                "X-RateLimit-Remaining": str(rate_limit_data.get("remaining", 5000)),
            }

            # Convert resetAt timestamp to Unix epoch
            reset_at = rate_limit_data.get("resetAt")
            if reset_at:
                from datetime import datetime

                reset_time = datetime.fromisoformat(reset_at.replace("Z", "+00:00"))
                headers["X-RateLimit-Reset"] = str(int(reset_time.timestamp()))

            # Update graphql resource quota specifically
            rate_limiter.update_quota_from_headers(token, headers, resource="graphql")

            # Log GraphQL query cost for debugging
            cost = rate_limit_data.get("cost", 1)
            remaining = rate_limit_data.get("remaining", 0)
            logger.debug(f"GraphQL query cost: {cost}, remaining: {remaining}")

        except (RuntimeError, ImportError):
            pass

    def execute_query(self, query: str, variables: Dict[str, Any]) -> Optional[Dict]:
        if self._graphql_disabled:
            return None

        try:
            from src.github_rate_limiter import get_rate_limiter

            rate_limiter = get_rate_limiter()
            # Wait if all tokens are rate limited
            if not rate_limiter.wait_if_rate_limited(resource="graphql", max_wait=3600):
                logger.error("Cannot proceed: rate limit wait time too long")
                return None
        except (RuntimeError, ImportError):
            time.sleep(constants.GITHUB_REQUEST_RATE_LIMIT)

        token = self._get_token()
        if not token:
            logger.error("No tokens available for GraphQL query")
            return None

        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        payload = {"query": query, "variables": variables}

        try:
            session = self._get_session()
            response = session.post(
                self.GRAPHQL_ENDPOINT,
                json=payload,
                headers=headers,
                timeout=constants.MAX_TIME_TO_SEARCH_GITHUB_REQUEST,
            )

            if response.status_code == 200:
                data = response.json()

                if "errors" in data:
                    for error in data["errors"]:
                        error_msg = error.get("message", "Unknown error")
                        error_type = error.get("type", "")

                        # Handle permission errors (token lacks GraphQL scope)
                        if (
                            "not accessible" in error_msg.lower()
                            or "forbidden" in error_msg.lower()
                            or "scope" in error_msg.lower()
                            or error_type == "FORBIDDEN"
                        ):
                            self._tokens_without_graphql.add(token)

                            # Get total number of tokens from rate limiter
                            try:
                                from src.github_rate_limiter import get_rate_limiter

                                rate_limiter = get_rate_limiter()
                                tokens_to_check = len(rate_limiter.tokens)
                            except (ImportError, RuntimeError, AttributeError) as e:
                                logger.debug(f"Could not get rate limiter token count: {e}")
                                tokens_to_check = (
                                    len(constants.GITHUB_TOKENS) if hasattr(constants, "GITHUB_TOKENS") else 2
                                )

                            tokens_checked = len(self._tokens_without_graphql) + len(self._tokens_with_graphql)

                            if tokens_checked >= tokens_to_check and tokens_to_check > 0:
                                if not self._graphql_disabled:
                                    logger.warning(
                                        f"All {tokens_to_check} tokens lack GraphQL API access (need 'repo' or 'public_repo' scope). Using REST API only."
                                    )
                                    self._graphql_disabled = True
                            else:
                                logger.debug(
                                    f"Current token lacks GraphQL access ({len(self._tokens_without_graphql)}/{tokens_to_check} tokens checked). Error: {error_msg}"
                                )

                        # Handle query complexity errors - disable GraphQL for this session
                        elif "resource limits" in error_msg.lower() or "exceeds maximum" in error_msg.lower():
                            logger.warning(
                                f"GraphQL query too complex: {error_msg}. This should not happen with optimized queries. Disabling GraphQL for this session."
                            )
                            self._graphql_disabled = True

                        else:
                            logger.error(f"GraphQL error: {error_msg}")
                    return None

                if token and token not in self._tokens_with_graphql:
                    self._tokens_with_graphql.add(token)
                    logger.debug("Token has GraphQL API access - will be preferred for future GraphQL requests")

                if "data" in data and data["data"] and "rateLimit" in data["data"]:
                    self._update_rate_limit(token, data["data"]["rateLimit"])

                return data

            elif response.status_code in (403, 429):
                logger.warning(f"GraphQL rate limit hit: {response.status_code}")
                try:
                    from src.github_rate_limiter import get_rate_limiter

                    rate_limiter = get_rate_limiter()
                    retry_after = response.headers.get("Retry-After")
                    if retry_after:
                        retry_after = int(retry_after)
                    rate_limiter.handle_rate_limit_error(token, retry_after, resource="graphql")
                except (RuntimeError, ImportError):
                    pass
                return None

            elif response.status_code == 401:
                # Authentication error - token is invalid or lacks required scopes
                if token and token not in self._tokens_without_graphql:
                    self._tokens_without_graphql.add(token)
                    logger.warning("Token authentication failed (401). Token marked as invalid for GraphQL.")

                # Check if all tokens are now invalid
                try:
                    from src.github_rate_limiter import get_rate_limiter

                    rate_limiter = get_rate_limiter()
                    tokens_to_check = len(rate_limiter.tokens)
                except (ImportError, RuntimeError, AttributeError):
                    tokens_to_check = len(constants.GITHUB_TOKENS) if hasattr(constants, "GITHUB_TOKENS") else 1

                tokens_checked = len(self._tokens_without_graphql) + len(self._tokens_with_graphql)

                if tokens_checked >= tokens_to_check and tokens_to_check > 0:
                    if not self._graphql_disabled:
                        logger.error(
                            f"All {tokens_to_check} GitHub tokens are invalid or lack required scopes for GraphQL API. Check token configuration."
                        )
                        self._graphql_disabled = True

                return None

            else:
                logger.error(f"GraphQL request failed: {response.status_code} - {response.text}")
                return None

        except Exception as e:
            logger.error(f"GraphQL request error: {e}")
            return None

    def _convert_repo_node(self, node: Dict) -> Optional[Dict]:
        """Convert GraphQL repository node to REST-like format."""
        if not node:
            return None
        try:
            return {
                "name": node.get("name"),
                "full_name": f"{node['owner']['login']}/{node['name']}",
                "owner": {"login": node["owner"]["login"]},
                "html_url": node.get("url"),
                "private": node.get("isPrivate", False),
                "created_at": node.get("createdAt"),
                "updated_at": node.get("updatedAt"),
                "pushed_at": node.get("pushedAt"),
                "description": node.get("description"),
                "stargazers_count": node.get("stargazerCount", 0),
                "forks_count": node.get("forkCount", 0),
                "watchers_count": node.get("watchers", {}).get("totalCount", 0),
                "open_issues_count": node.get("issues", {}).get("totalCount", 0),
                "has_issues": node.get("hasIssuesEnabled", False),
                "has_projects": node.get("hasProjectsEnabled", False),
                "has_wiki": node.get("hasWikiEnabled", False),
                "has_downloads": False,
                "size": node.get("diskUsage", 0),
                "language": node.get("primaryLanguage", {}).get("name") if node.get("primaryLanguage") else None,
                "topics": [t["topic"]["name"] for t in node.get("repositoryTopics", {}).get("nodes", []) if t and t.get("topic")],
                "languages": {e["node"]["name"]: e["size"] for e in node.get("languages", {}).get("edges", []) if e and e.get("node")},
                "collaborators_count": node.get("collaborators", {}).get("totalCount", 0),
                "commit_count": node.get("defaultBranchRef", {}).get("target", {}).get("history", {}).get("totalCount", 0) if node.get("defaultBranchRef") else 0,
            }
        except (KeyError, TypeError) as e:
            logger.debug(f"Error converting repo node: {e}")
            return None

    def _convert_code_node(self, node: Dict) -> Optional[Dict]:
        """Convert GraphQL code node to REST-like format."""
        if not node or not node.get("repository"):
            return None
        try:
            repo = node["repository"]
            return {
                "name": node.get("path", "").split("/")[-1],
                "path": node.get("path"),
                "html_url": f"{repo.get('url')}/blob/master/{node.get('path')}",
                "repository": {
                    "name": repo.get("name"),
                    "full_name": f"{repo['owner']['login']}/{repo['name']}",
                    "owner": {"login": repo["owner"]["login"]},
                    "html_url": repo.get("url"),
                    "private": repo.get("isPrivate", False),
                    "created_at": repo.get("createdAt"),
                    "updated_at": repo.get("updatedAt"),
                    "description": repo.get("description"),
                    "stargazers_count": repo.get("stargazerCount", 0),
                    "forks_count": repo.get("forkCount", 0),
                    "size": repo.get("diskUsage", 0),
                },
                "text_matches": [{"fragment": node.get("text", "")}] if node.get("text") else [],
            }
        except (KeyError, TypeError) as e:
            logger.debug(f"Error converting code node: {e}")
            return None

    def search_repositories_with_stats(self, query: str, max_results: int = 100) -> List[Dict]:
        """
        Search repositories and get stats in one query.

        This is more efficient than REST API as it gets all repo data
        including statistics in a single request.

        Args:
            query: Search query (same format as REST API)
            max_results: Maximum number of results to retrieve

        Returns:
            List of repositories with embedded statistics
        """
        results = []
        has_next_page = True
        cursor = None

        # Use small batch size (10) to stay within complexity limits
        # Query includes expensive nested fields: languages, topics, defaultBranchRef, collaborators
        # GitHub GraphQL cost = base_cost + (result_count × field_complexity)
        BATCH_SIZE = 10

        while has_next_page and len(results) < max_results:
            variables = {"query": query, "first": min(BATCH_SIZE, max_results - len(results)), "after": cursor}

            # Choose query based on permission level
            query_to_use = (
                self.SEARCH_REPOS_WITH_STATS_LIMITED if self.use_limited_queries else self.SEARCH_REPOS_WITH_STATS
            )
            data = self.execute_query(query_to_use, variables)

            # If we got a permission error and not using limited queries yet, switch and retry
            if data and "errors" in data and not self.use_limited_queries:
                for error in data.get("errors", []):
                    error_msg = error.get("message", "").lower()
                    if "not accessible" in error_msg or "forbidden" in error_msg:
                        logger.info("Switching to limited GraphQL queries (without collaborators field)")
                        self.use_limited_queries = True
                        data = self.execute_query(self.SEARCH_REPOS_WITH_STATS_LIMITED, variables)
                        break
            if not data or "data" not in data or not data["data"]:
                break

            search_data = data["data"]["search"]

            # Convert nodes using helper method
            for node in search_data.get("nodes", []):
                repo_data = self._convert_repo_node(node)
                if repo_data:
                    results.append(repo_data)

            page_info = search_data.get("pageInfo", {})
            has_next_page = page_info.get("hasNextPage", False)
            cursor = page_info.get("endCursor")

            total_count = search_data.get("repositoryCount", 0)
            logger.info(f"Retrieved {len(results)}/{min(total_count, max_results)} repositories via GraphQL")

        return results

    def search_code_with_context(self, query: str, max_results: int = 100) -> List[Dict]:
        """
        Search code with repository context.

        Args:
            query: Search query
            max_results: Maximum results

        Returns:
            List of code results with repository data
        """
        results = []
        has_next_page = True
        cursor = None
        BATCH_SIZE = 10

        while has_next_page and len(results) < max_results:
            variables = {"query": query, "first": min(BATCH_SIZE, max_results - len(results)), "after": cursor}

            data = self.execute_query(self.SEARCH_CODE_WITH_CONTEXT, variables)
            if not data or "data" not in data or not data["data"]:
                break

            search_data = data["data"]["search"]

            # Convert nodes using helper method
            for node in search_data.get("nodes", []):
                code_result = self._convert_code_node(node)
                if code_result:
                    results.append(code_result)

            page_info = search_data.get("pageInfo", {})
            has_next_page = page_info.get("hasNextPage", False)
            cursor = page_info.get("endCursor")

            logger.info(f"Retrieved {len(results)} code results via GraphQL")

        return results

    # Query for fetching complete repository stats (repo info + contributors + commits) in ONE request
    GET_REPO_FULL_STATS = """
    query GetRepoFullStats($owner: String!, $name: String!) {
      repository(owner: $owner, name: $name) {
        createdAt
        updatedAt
        pushedAt
        description
        stargazerCount
        forkCount
        watchers { totalCount }
        issues(states: OPEN) { totalCount }
        hasIssuesEnabled
        hasProjectsEnabled
        hasWikiEnabled
        diskUsage
        repositoryTopics(first: 10) { nodes { topic { name } } }
        defaultBranchRef {
          name
          target {
            ... on Commit {
              history(first: 30) {
                totalCount
                nodes {
                  author {
                    name
                    email
                    user { login }
                  }
                }
              }
            }
          }
        }
        mentionableUsers(first: 30) {
          totalCount
          nodes { login }
        }
      }
      rateLimit { limit remaining resetAt cost }
    }
    """

    def get_repository_full_stats(self, owner: str, name: str) -> Optional[Dict]:
        """
        Fetch complete repository statistics in a single GraphQL query.
        
        Returns repo info, contributors, and commit authors all at once,
        saving 2 API calls compared to REST API approach.
        
        Args:
            owner: Repository owner (username or org)
            name: Repository name
            
        Returns:
            Dict with parsed stats or None if failed/not found
        """
        if self._graphql_disabled:
            return None

        variables = {"owner": owner, "name": name}
        data = self.execute_query(self.GET_REPO_FULL_STATS, variables)

        if not data or "data" not in data or not data["data"]:
            return None

        repo = data["data"].get("repository")
        
        # Repository not found (deleted/private)
        if repo is None:
            return {"error": "not_found", "message": "Repository not found (deleted or private)"}

        try:
            # Parse timestamps
            created_at = repo.get("createdAt", "")
            updated_at = repo.get("updatedAt", "")
            
            # Extract topics
            topics = []
            repo_topics = repo.get("repositoryTopics", {})
            if isinstance(repo_topics, dict):
                for t in repo_topics.get("nodes", []):
                    if isinstance(t, dict) and "topic" in t and isinstance(t["topic"], dict):
                        topic_name = t["topic"].get("name")
                        if topic_name:
                            topics.append(topic_name)

            # Extract contributors from mentionableUsers
            contributors = []
            mentionable = repo.get("mentionableUsers", {})
            if isinstance(mentionable, dict):
                contributors_count = mentionable.get("totalCount", 0)
                for user in mentionable.get("nodes", []):
                    if isinstance(user, dict) and "login" in user:
                        contributors.append({"login": user["login"]})
            else:
                contributors_count = 0

            # Extract commits and authors
            commits_count = 0
            commit_authors = []
            seen_emails = set()
            
            default_branch = repo.get("defaultBranchRef")
            if isinstance(default_branch, dict):
                target = default_branch.get("target", {})
                if isinstance(target, dict):
                    history = target.get("history", {})
                    if isinstance(history, dict):
                        commits_count = history.get("totalCount", 0)
                        for commit in history.get("nodes", []):
                            if not isinstance(commit, dict):
                                continue
                            author = commit.get("author", {})
                            if not isinstance(author, dict):
                                continue
                            email = author.get("email", "")
                            name = author.get("name", "")
                            if email and email not in seen_emails:
                                seen_emails.add(email)
                                commit_authors.append({
                                    "name": name,
                                    "email": email,
                                    "login": author.get("user", {}).get("login") if author.get("user") else None
                                })

            # Safe extraction helpers
            def safe_count(obj, key, default=0):
                if isinstance(obj, dict):
                    nested = obj.get(key, {})
                    if isinstance(nested, dict):
                        return nested.get("totalCount", default)
                return default

            return {
                "found": True,
                "created_at": created_at,
                "updated_at": updated_at,
                "pushed_at": repo.get("pushedAt", ""),
                "description": repo.get("description") or "",
                "size": repo.get("diskUsage", 0),
                "stargazers_count": repo.get("stargazerCount", 0),
                "forks_count": repo.get("forkCount", 0),
                "watchers_count": safe_count(repo, "watchers"),
                "open_issues_count": safe_count(repo, "issues"),
                "has_issues": repo.get("hasIssuesEnabled", False),
                "has_projects": repo.get("hasProjectsEnabled", False),
                "has_wiki": repo.get("hasWikiEnabled", False),
                "topics": topics,
                "contributors_count": contributors_count,
                "contributors": contributors,
                "commits_count": commits_count,
                "commit_authors": commit_authors,
            }

        except Exception as e:
            logger.debug(f"Error parsing repo stats: {e}")
            return None


# Global GraphQL client instance
_graphql_client: Optional[GitHubGraphQLClient] = None


def get_graphql_client() -> GitHubGraphQLClient:
    """Get or create global GraphQL client instance."""
    global _graphql_client
    if _graphql_client is None:
        _graphql_client = GitHubGraphQLClient()
    return _graphql_client
