# Standart libs import
from abc import ABC, abstractmethod
import json
import time
import requests
from math import ceil

# Project lib's import

from src.utils import filter_url_by_db, filter_url_by_repo
from src.logger import logger

from src.LeakObj import CodeObj, RepoObj, CommitObj

from src import constants


# TODO: Implement configurable max pages limit
# Currently pagination continues until all results are fetched or rate limit hit.
# Add MAX_PAGES constant to limit memory usage and API calls for large result sets.
# Suggested implementation: Add `max_pages` parameter to get_pages() method.


class GitParserSearch(ABC):
    # attrs to override
    url: str
    T: callable

    # limits
    timeout: int = constants.MAX_TIME_TO_SEARCH_GITHUB_REQUEST
    cooldown: float = constants.GITHUB_REQUEST_COOLDOWN
    rate_limit: float = constants.GITHUB_REQUEST_RATE_LIMIT
    repo_count_limit: int = constants.GITHUB_REPO_COUNT_AT_REQUEST_LIMIT
    per_page: int = constants.GITHUB_REQUEST_REPO_PER_PAGE

    def __init__(self, dork: str, organization: int):
        self.dork: str = dork
        self.organization: int = organization
        self.pages: int = 1
        self.last_request: float = 0.0
        self.params: dict = {"q": dork, "per_page": self.per_page}

        if self.url is None:
            raise ValueError("Attribute url is not overloaded!")
        if self.T is None:
            raise ValueError("Attribute T is not overloaded!")

    @abstractmethod
    def __str__(self) -> str:
        pass

    def to_obj(self, json_resp):
        return tuple(
            self.T(repo["html_url"], repo, self.dork.encode().decode("utf-8"), self.organization)
            for repo in json_resp["items"]
            if len(filter_url_by_db(repo["html_url"])) == 1 and len(filter_url_by_repo(repo["html_url"])) == 1
        )

    def request_page(self) -> requests.Response:
        """Send API request with rate limiting."""
        # Determine resource type based on parser class
        is_code_search = "code" in self.url.lower()
        resource_type = "search_code" if is_code_search else "search"

        try:
            from src.github_rate_limiter import get_rate_limiter

            rate_limiter = get_rate_limiter()

            # Enforce Search API limit (10/min for code, 30/min for others)
            rate_limiter.wait_for_search_rate_limit(is_code_search=is_code_search)

            # Get best available token for this resource type
            token = rate_limiter.get_best_token(resource=resource_type)
            if token is None:
                logger.warning("No tokens available, waiting 60s...")
                time.sleep(60)
                token = rate_limiter.get_best_token(resource=resource_type)
        except (RuntimeError, ImportError):
            # Fallback to old behavior if rate limiter not available
            token = next(constants.token_generator())

        headers = {"Authorization": f"Token {token}"} if token else {}
        response = requests.get(url=self.url, params=self.params, headers=headers, timeout=self.timeout)

        # Update quota from response with correct resource type
        try:
            from src.github_rate_limiter import get_rate_limiter

            rate_limiter = get_rate_limiter()
            rate_limiter.update_quota_from_headers(token, response.headers, resource=resource_type)

            # Handle rate limit errors
            if response.status_code in (403, 429):
                retry_after = response.headers.get("Retry-After")
                if retry_after:
                    retry_after = int(retry_after)
                rate_limiter.handle_rate_limit_error(token, retry_after, resource=resource_type)
        except (RuntimeError, ImportError):
            pass

        return response

    def get_pages(self):  # -> Generator[tuple[T]]:
        """Generator with improved error handling and rate limiting."""
        page: int = 1
        consecutive_errors = 0
        max_errors = 5

        while page <= self.pages:
            self.params["page"] = page

            try:
                # Rate limiting is now in request_page
                response = self.request_page()
                self.last_request = time.time()
                logger.info(f"GitHub API Search request performed (page {page}/{self.pages})")

                # SUCCESS
                if response.status_code == 200:
                    consecutive_errors = 0
                    try:
                        json_resp = response.json()
                    except ValueError as e:
                        logger.error(f"Failed to parse JSON: {e}")
                        consecutive_errors += 1
                        continue

                    self.pages = ceil(min(json_resp["total_count"], self.repo_count_limit) / self.per_page)
                    yield self.to_obj(json_resp)
                    page += 1
                    constants.dork_search_counter += 1

                # RATE LIMIT
                elif response.status_code in (403, 429):
                    try:
                        error_msg = response.json().get("message", "").lower()
                    except (json.JSONDecodeError, ValueError, AttributeError):
                        error_msg = response.text.lower()

                    if "rate limit" in error_msg or "api rate limit" in error_msg:
                        reset_time = int(response.headers.get("X-RateLimit-Reset", 0))
                        retry_after = int(response.headers.get("Retry-After", 0))
                        wait_time = max(reset_time - time.time() if reset_time else 0, retry_after, 60)
                        logger.warning(f"Rate limit exceeded. Waiting {wait_time:.0f}s...")
                        time.sleep(wait_time)
                        consecutive_errors = 0  # Don't count as error
                    elif "abuse" in error_msg:
                        logger.error("GitHub abuse detection triggered. Waiting 5 minutes...")
                        time.sleep(300)
                        consecutive_errors += 1
                    else:
                        logger.error(f"Access denied (403): {error_msg}")
                        consecutive_errors += 1
                        if consecutive_errors >= 3:
                            logger.error("Repeated access errors, stopping")
                            return

                # INVALID QUERY
                elif response.status_code == 422:
                    try:
                        error_data = response.json()
                        logger.error(f"Invalid query (422): {error_data.get('message', response.text)}")
                    except (json.JSONDecodeError, ValueError):
                        logger.error(f"Invalid query (422): {response.text}")
                    return  # Stop this dork

                # SERVER ERROR
                elif response.status_code >= 500:
                    wait_time = min(2**consecutive_errors, 300)
                    logger.error(
                        f"Server error {response.status_code}. Waiting {wait_time}s (attempt {consecutive_errors + 1})"
                    )
                    time.sleep(wait_time)
                    consecutive_errors += 1

                # OTHER
                else:
                    logger.error(f"Unexpected status {response.status_code}: {response.text[:200]}")
                    consecutive_errors += 1
                    time.sleep(self.cooldown)

                if consecutive_errors >= max_errors:
                    logger.error(f"Too many errors ({consecutive_errors}), stopping")
                    return

            except requests.Timeout:
                logger.error(f"Request timeout after {self.timeout}s")
                consecutive_errors += 1
                time.sleep(min(2**consecutive_errors, 60))
                if consecutive_errors >= max_errors:
                    return

            except requests.RequestException as ex:
                logger.error(f"Request error: {ex}")
                consecutive_errors += 1
                time.sleep(min(2**consecutive_errors, 60))
                if consecutive_errors >= max_errors:
                    return

            except Exception as ex:
                logger.error(f"Unexpected error: {ex}", exc_info=True)
                return


class GitCodeParser(GitParserSearch):
    url: str = "https://api.github.com/search/code"
    T = CodeObj

    def __init__(self, dork: str, organization: int):
        super().__init__(dork, organization)
        self.params["sort"] = "indexed"
        self.params["order"] = "desc"

    def __str__(self) -> str:
        return "GitCodeParser"


class GitRepoParser(GitParserSearch):
    url: str = "https://api.github.com/search/repositories"
    T = RepoObj
    use_graphql: bool = True  # Enable GraphQL for better efficiency

    def __init__(self, dork: str, organization: int):
        super().__init__(dork, organization)
        self.params["sort"] = "updated"
        self.params["order"] = "desc"

    def __str__(self) -> str:
        return "GitRepoParser"

    def get_pages(self):
        """Override to use GraphQL when possible."""
        if self.use_graphql:
            try:
                from src.searcher.graphql_client import get_graphql_client

                graphql_client = get_graphql_client()

                # Use GraphQL to get repos with stats in one query
                logger.info(f"Using GraphQL for repo search: {self.dork}")
                repos = graphql_client.search_repositories_with_stats(
                    self.dork, max_results=min(self.repo_count_limit, 1000)
                )

                if repos:
                    # Convert to RepoObj format
                    repo_objects = tuple(
                        self.T(repo["html_url"], repo, self.dork, self.organization)
                        for repo in repos
                        if len(filter_url_by_db(repo["html_url"])) == 1
                        and len(filter_url_by_repo(repo["html_url"])) == 1
                    )

                    if repo_objects:
                        constants.dork_search_counter += 1
                        yield repo_objects

                    logger.info(f"GraphQL returned {len(repos)} repositories")
                    return
                else:
                    logger.warning("GraphQL returned no results, falling back to REST")
            except Exception as e:
                logger.warning(f"GraphQL failed: {e}, falling back to REST API")

        # Fallback to REST API
        yield from super().get_pages()


class GitCommitParser(GitParserSearch):
    url: str = "https://api.github.com/search/commits"
    T = CommitObj

    def __init__(self, dork: str, organization: int):
        super().__init__(dork, organization)
        self.params["sort"] = "commiter-date"
        self.params["order"] = "desc"

    def __str__(self) -> str:
        return "GitCommitParser"
