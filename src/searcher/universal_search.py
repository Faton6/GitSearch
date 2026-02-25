"""Universal GitHub Search Client with REST and GraphQL support."""

import time
import requests
from typing import Dict, List, Optional, Generator
from math import ceil
from enum import Enum

from src.logger import logger
from src import constants


class SearchType(Enum):
    """Types of GitHub searches."""

    REPOSITORIES = "repositories"
    CODE = "code"
    COMMITS = "commits"
    GISTS = "gists"
    ISSUES = "issues"


class UniversalGitHubSearch:
    """Universal GitHub search with GraphQL (repos/code) and REST API (gists) support."""

    def __init__(self, search_type: SearchType, use_graphql: bool = True):
        self.search_type = search_type
        self.use_graphql = use_graphql
        self._setup_endpoints()

    def _setup_endpoints(self):
        base_url = "https://api.github.com/search"

        self.rest_endpoint = {
            SearchType.REPOSITORIES: f"{base_url}/repositories",
            SearchType.CODE: f"{base_url}/code",
            SearchType.COMMITS: f"{base_url}/commits",
            SearchType.GISTS: "https://api.github.com/gists/public",
            SearchType.ISSUES: f"{base_url}/issues",
        }.get(self.search_type)

        # GraphQL queries are now handled by graphql_client.py
        # This list defines which search types support GraphQL
        self.graphql_supported_types = {SearchType.REPOSITORIES, SearchType.CODE}

    def _get_token(self) -> Optional[str]:
        # Determine resource type based on search type
        is_code_search = self.search_type == SearchType.CODE
        resource_type = "search_code" if is_code_search else "search"

        try:
            from src.github_rate_limiter import get_rate_limiter

            rate_limiter = get_rate_limiter()

            # Wait for rate limit (10/min for code, 30/min for others)
            if self.search_type in (SearchType.REPOSITORIES, SearchType.CODE, SearchType.COMMITS):
                rate_limiter.wait_for_search_rate_limit(is_code_search=is_code_search)

            # Check if all tokens exhausted and wait if needed
            if not rate_limiter.wait_if_rate_limited(resource=resource_type, max_wait=3600):
                logger.error(f"All tokens rate limited for '{resource_type}' and wait time exceeds 1 hour")
                return None

            token = rate_limiter.get_best_token(resource=resource_type)

            return token
        except (RuntimeError, ImportError):
            # Fallback
            return next(constants.token_generator())

    def _update_rate_limit(self, token: str, headers: Dict[str, str]):
        # Determine resource type based on search type
        is_code_search = self.search_type == SearchType.CODE
        resource_type = "search_code" if is_code_search else "search"

        try:
            from src.github_rate_limiter import get_rate_limiter

            rate_limiter = get_rate_limiter()
            rate_limiter.update_quota_from_headers(token, headers, resource=resource_type)

            if int(headers.get("X-RateLimit-Remaining", 5000)) < 100:
                logger.warning(f"Low quota: {headers.get('X-RateLimit-Remaining')}/{headers.get('X-RateLimit-Limit')}")
        except (RuntimeError, ImportError):
            pass

    def _handle_rate_limit_error(self, token: str, response: requests.Response):
        # Determine resource type based on search type
        is_code_search = self.search_type == SearchType.CODE
        resource_type = "search_code" if is_code_search else "search"

        try:
            from src.github_rate_limiter import get_rate_limiter

            rate_limiter = get_rate_limiter()

            retry_after = response.headers.get("Retry-After")
            if retry_after:
                retry_after = int(retry_after)
            rate_limiter.handle_rate_limit_error(token, retry_after, resource=resource_type)
        except (RuntimeError, ImportError):
            # Fallback
            retry_after = int(response.headers.get("Retry-After", 60))
            logger.warning(f"Rate limit hit, waiting {retry_after}s")
            time.sleep(retry_after)

    def _search_graphql(self, query: str, max_results: int = 100) -> List[Dict]:
        """Execute GraphQL search using optimized methods from graphql_client."""
        if self.search_type not in self.graphql_supported_types:
            return []

        try:
            from src.searcher.graphql_client import get_graphql_client

            graphql_client = get_graphql_client()

            # Use optimized methods from graphql_client that handle pagination,
            # rate limiting, and data conversion internally
            if self.search_type == SearchType.REPOSITORIES:
                results = graphql_client.search_repositories_with_stats(query, max_results)
            elif self.search_type == SearchType.CODE:
                results = graphql_client.search_code_with_context(query, max_results)
            else:
                return []

            logger.debug(f"GraphQL retrieved {len(results)} results")
            return results

        except Exception as e:
            logger.warning(f"GraphQL search failed: {e}")
            return []

    def _search_rest(
        self, query: str, max_results: int = 100, per_page: int = 100
    ) -> Generator[List[Dict], None, None]:
        page = 1
        max_pages = ceil(min(max_results, 1000) / per_page)
        consecutive_errors = 0
        max_errors = 5

        while page <= max_pages:
            token = self._get_token()
            headers = {"Authorization": f"Token {token}"} if token else {}

            if self.search_type == SearchType.GISTS:
                url = self.rest_endpoint
                params = {"per_page": per_page, "page": page}
            else:
                url = self.rest_endpoint
                params = {"q": query, "per_page": per_page, "page": page, "sort": "updated", "order": "desc"}

            try:
                response = requests.get(
                    url, params=params, headers=headers, timeout=constants.MAX_TIME_TO_SEARCH_GITHUB_REQUEST
                )

                if token:
                    self._update_rate_limit(token, response.headers)

                if response.status_code == 200:
                    consecutive_errors = 0
                    data = response.json()

                    if self.search_type == SearchType.GISTS:
                        items = data if isinstance(data, list) else []
                        if query:
                            items = [
                                item
                                for item in items
                                if (item.get("description") and query.lower() in item.get("description").lower())
                                or any(query.lower() in f.lower() for f in item.get("files", {}))
                            ]
                    else:
                        items = data.get("items", [])

                    if items:
                        yield items
                        page += 1
                        constants.dork_search_counter += 1
                    else:
                        break

                elif response.status_code in (403, 429):
                    if token:
                        self._handle_rate_limit_error(token, response)
                    consecutive_errors = 0

                elif response.status_code == 422:
                    logger.error(f"Invalid query: {response.text[:200]}")
                    break

                elif response.status_code >= 500:
                    wait_time = min(2**consecutive_errors, 300)
                    logger.error(f"Server error {response.status_code}, waiting {wait_time}s")
                    time.sleep(wait_time)
                    consecutive_errors += 1

                else:
                    logger.error(f"Unexpected status {response.status_code}: {response.text[:200]}")
                    consecutive_errors += 1
                    time.sleep(10)

                if consecutive_errors >= max_errors:
                    logger.error(f"Too many errors ({consecutive_errors}), stopping")
                    break

            except requests.RequestException as e:
                logger.error(f"Request error: {e}")
                consecutive_errors += 1
                time.sleep(min(2**consecutive_errors, 60))
                if consecutive_errors >= max_errors:
                    break

    def search(self, query: str, max_results: int = 100) -> Generator[List[Dict], None, None]:
        if self.search_type == SearchType.GISTS:
            logger.info(f"Using REST API for {self.search_type.value}: {query}")
            yield from self._search_rest(query, max_results)
            return

        graphql_available = False
        if self.use_graphql and self.search_type in self.graphql_supported_types:
            try:
                from src.searcher.graphql_client import get_graphql_client

                graphql_client = get_graphql_client()
                graphql_available = not graphql_client._graphql_disabled
            except (ImportError, RuntimeError, AttributeError) as e:
                logger.debug(f"GraphQL client not available: {e}")

        if graphql_available:
            try:
                logger.info(f"Attempting GraphQL search for {self.search_type.value}: {query}")
                results = self._search_graphql(query, max_results)

                if results:
                    logger.info(f"GraphQL returned {len(results)} results")
                    yield results
                    return
                else:
                    logger.info("GraphQL returned no results, falling back to REST")
            except Exception as e:
                logger.warning(f"GraphQL search failed: {e}, falling back to REST")

        logger.info(f"Using REST API for {self.search_type.value}: {query}")
        yield from self._search_rest(query, max_results)
