import requests
import time
import re
from random import choice

from src.logger import logger, CLR
from src import constants


class GitParserStats:
    # attrs to override
    login_repo: str

    # limits
    timeout: int = 30
    cooldown: float = 60.0
    rate_limit: float = 10.0

    def __init__(self, html_url: str):
        self.login_repo = html_url.split("github.com/")[1]
        self.login_repo = self.login_repo.split("/")[0] + "/" + self.login_repo.split("/")[1]
        if "gist.github.com" in html_url:
            self.type = "Gist"
            self.repo_url: str = "https://api.github.com/gists/" + self.login_repo.split("/")[1]
            self.commits_url: str = self.repo_url + "/commits"
        else:
            self.type = "Repository"
            self.repo_url: str = "https://api.github.com/repos/" + self.login_repo
            self.contributors_url: str = self.repo_url + "/contributors"
            self.commits_url: str = self.repo_url + "/commits"
        self.last_request: float = 0.0
        self.log_color = choice(tuple(CLR.values()))
        self.created_at = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self.updated_at = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self.repo_stats_leak_stats_table: dict = {
            "size": 0,
            "stargazers_count": 0,
            "has_issues": 0,
            "has_projects": 0,
            "has_downloads": 0,
            "has_wiki": 0,
            "has_pages": 0,
            "forks_count": 0,
            "open_issues_count": 0,
            "subscribers_count": 0,
            "topics": "_",
            "contributors_count": 0,
            "commits_count": 0,
            "commiters_count": 0,
            "ai_result": -1,  # 1 - ai found leak, 0 - ai not found leak, -1 - ai not used
            "description": "_",
        }

        self.contributors_stats_accounts_table: list = []

        self.commits_stats_commiters_table: list = []

        self.ai_result = -1  # 1 - ai found leak, 0 - ai not found leak, -1 - ai not used

        self.repo_stats_getted = False
        self.coll_stats_getted = False
        self.comm_stats_getted = False

        self.is_inaccessible = False
        self.inaccessibility_reason = ""

        if self.login_repo is None:
            raise ValueError("Attribute url is not overloaded!")

    def _is_corporate_domain(self, email: str) -> bool:
        """Check if email domain is corporate (not a public provider)."""
        from src.utils import extract_domain_from_email

        domain = extract_domain_from_email(email)
        return domain and domain not in constants.PUBLIC_EMAIL_DOMAINS

    # Pre-compiled dangerous patterns (class-level)
    _dangerous_patterns_compiled = None

    @classmethod
    def _get_dangerous_patterns(cls):
        """Get compiled dangerous patterns (lazy initialization)."""
        if cls._dangerous_patterns_compiled is None:
            cls._dangerous_patterns_compiled = [
                re.compile(r"\b" + re.escape(pattern) + r"\b", re.IGNORECASE)
                for pattern in constants.DANGEROUS_PATTERNS
            ]
        return cls._dangerous_patterns_compiled

    def _contains_dangerous_patterns(self, repo_name: str, committer_name: str = "") -> bool:
        """Check if repository or committer info contains dangerous patterns with word boundaries."""
        text_to_check = f"{repo_name} {committer_name}"
        patterns = self._get_dangerous_patterns()
        return any(pattern.search(text_to_check) for pattern in patterns)

    def _calculate_monitoring_score(self, committer_email: str, repo_name: str, committer_name: str = "") -> int:
        """Calculate if account needs monitoring based on domain and dangerous patterns."""
        score = 0

        # Corporate domain increases monitoring score
        if self._is_corporate_domain(committer_email):
            score += 1

        # Dangerous patterns increase monitoring score
        if self._contains_dangerous_patterns(repo_name, committer_name):
            score += 1

        # Return 1 if score >= 1 (needs monitoring), 0 otherwise
        return 1 if score >= 1 else 0

    def _handle_github_error_response(self, response: dict, context: str = "") -> bool:
        if not isinstance(response, dict) or "message" not in response:
            return False

        status = response.get("status", "")
        message = response.get("message", "")

        if status == "409" and "empty" in message.lower():
            logger.info(f"Repository is empty ({context}): {self.login_repo}")
            self.is_inaccessible = True
            self.inaccessibility_reason = "Репозиторий пустой (нет коммитов)"
            return True
        elif status == "404":
            logger.warning(f"Resource not found ({context}): {self.login_repo}")
            self.is_inaccessible = True
            self.inaccessibility_reason = "Репозиторий не найден (удален или приватный)"
            return True
        elif status == "403":
            logger.warning(f"Access forbidden ({context}): {self.login_repo}")
            self.is_inaccessible = True
            self.inaccessibility_reason = "Доступ к репозиторию запрещен"
            return True
        else:
            logger.error(f'Got message from github request ({context}): {self.log_color} {response} {CLR["RESET"]}')
            return True

    def _fetch_stats_via_graphql(self) -> bool:
        try:
            from src.searcher.graphql_client import get_graphql_client

            graphql_client = get_graphql_client()

            query = """
            query GetRepoStats($owner: String!, $name: String!) {
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
                repositoryTopics(first: 10) {
                  nodes { topic { name } }
                }
                defaultBranchRef {
                  target {
                    ... on Commit {
                      history { totalCount }
                    }
                  }
                }
              }
            }
            """

            owner, name = self.login_repo.split("/")
            variables = {"owner": owner, "name": name}

            data = graphql_client.execute_query(query, variables)

            if data and "data" in data and data["data"] and "repository" in data["data"]:
                repo = data["data"]["repository"]

                # Check if repository is null (not found/deleted/private)
                if repo is None:
                    logger.info(f"Repository not found via GraphQL: {self.login_repo}")
                    self.is_inaccessible = True
                    self.inaccessibility_reason = "Репозиторий не найден (удален или приватный)"
                    self.repo_stats_getted = True
                    return True

                # Parse timestamps
                self.created_at = time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.strptime(repo["createdAt"], "%Y-%m-%dT%H:%M:%SZ")
                )
                self.updated_at = time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.strptime(repo["updatedAt"], "%Y-%m-%dT%H:%M:%SZ")
                )

                # Import safe helpers from utils
                from src.utils import safe_get_count, safe_get_nested

                # Безопасное извлечение topics
                topics_value = "_"
                repo_topics = repo.get("repositoryTopics")
                if isinstance(repo_topics, dict):
                    nodes = repo_topics.get("nodes", [])
                    if isinstance(nodes, list):
                        topics_value = (
                            ",".join(
                                [
                                    t["topic"]["name"]
                                    for t in nodes
                                    if isinstance(t, dict) and "topic" in t and "name" in t.get("topic", {})
                                ]
                            )
                            or "_"
                        )

                self.repo_stats_leak_stats_table = {
                    "size": repo.get("diskUsage", 0),
                    "stargazers_count": repo.get("stargazerCount", 0),
                    "has_issues": 1 if repo.get("hasIssuesEnabled") else 0,
                    "has_projects": 1 if repo.get("hasProjectsEnabled") else 0,
                    "has_downloads": 0,
                    "has_wiki": 1 if repo.get("hasWikiEnabled") else 0,
                    "has_pages": 0,
                    "forks_count": repo.get("forkCount", 0),
                    "open_issues_count": safe_get_count(repo, "issues", 0),
                    "subscribers_count": safe_get_count(repo, "watchers", 0),
                    "topics": topics_value,
                    "contributors_count": 0,
                    "commits_count": safe_get_nested(
                        repo, "defaultBranchRef", "target", "history", "totalCount", default=0
                    ),
                    "commiters_count": 0,
                    "ai_result": -1,
                    "description": repo.get("description", "_") or "_",
                }

                self.repo_stats_getted = True

                # Check if repository is empty (diskUsage=0) - mark as inaccessible
                if self.repo_stats_leak_stats_table.get("size", 0) == 0:
                    logger.info(f"Repository has zero size (GraphQL), marking as inaccessible: {self.login_repo}")
                    self.is_inaccessible = True
                    self.inaccessibility_reason = "Репозиторий пустой (размер 0 байт)"
                    self.coll_stats_getted = True  # Skip contributors
                    self.comm_stats_getted = True  # Skip commits

                logger.debug(f"Fetched stats via GraphQL for {self.login_repo}")
                return True
            elif data and "errors" in data:
                logger.debug(f'GraphQL query returned errors: {data["errors"]}')
        except Exception as e:
            logger.debug(f"GraphQL stats fetch failed: {e}")

        return False

    # check repository stats:
    def fetch_repository_stats(self):  # Renamed from get_repo_stats for better clarity
        if self.type == "Repository" and not self.repo_stats_getted:
            try:
                from src.searcher.graphql_client import get_graphql_client

                graphql_client = get_graphql_client()
                if not graphql_client._graphql_disabled:
                    if self._fetch_stats_via_graphql():
                        return
                    # Don't fallback to REST if GraphQL marked as inaccessible
                    if self.is_inaccessible:
                        return
            except (ImportError, RuntimeError, Exception) as e:
                logger.debug(f"GraphQL client initialization failed: {e}")

        try:
            response_obj = self.request_page(self.repo_url, wait_if_no_tokens=False)

            if response_obj is None:
                logger.error("No tokens available for stats, skipping repository")
                self.is_inaccessible = True
                self.inaccessibility_reason = "Нет доступных токенов GitHub API"
                self.repo_stats_getted = True
                return

            try:
                response = response_obj.json()
            except ValueError:
                if response_obj.status_code == 200:
                    logger.warning(f"Invalid JSON response from {self.repo_url}: {response_obj.text[:100]}")
                response = {
                    "message": f"Invalid JSON (status {response_obj.status_code})",
                    "status": str(response_obj.status_code),
                }

        except requests.RequestException as ex:
            logger.error(
                f"Request Error in getting {self.type} stats of %s %s %s {self.type}: %s %s %s",
                self.log_color,
                self.repo_url,
                CLR["RESET"],
                self.log_color,
                ex,
                CLR["RESET"],
            )
            self.repo_stats_getted = True
            return

        if isinstance(response, dict) and "message" not in response:
            self.created_at = time.strftime(
                "%Y-%m-%d %H:%M:%S", time.strptime(response["created_at"], "%Y-%m-%dT%H:%M:%SZ")
            )
            self.updated_at = time.strftime(
                "%Y-%m-%d %H:%M:%S", time.strptime(response["updated_at"], "%Y-%m-%dT%H:%M:%SZ")
            )

            if self.type == "Gist":
                full_size = 0
                if "files" in response:
                    files_data = response["files"]
                    if isinstance(files_data, dict):
                        full_size = sum(f.get("size", 0) for f in files_data.values() if isinstance(f, dict))

                # Handle forks
                forks_count = 0
                if "forks" in response:
                    if isinstance(response["forks"], list):
                        forks_count = len(response["forks"])
                    elif isinstance(response["forks"], int):
                        forks_count = response["forks"]

                description = response.get("description") or "_"

                self.repo_stats_leak_stats_table = {
                    "size": full_size,
                    "stargazers_count": 0,
                    "has_issues": 0,
                    "has_projects": 0,
                    "has_downloads": 0,
                    "has_wiki": 0,
                    "has_pages": 0,
                    "forks_count": forks_count,
                    "open_issues_count": 0,
                    "subscribers_count": 0,
                    "topics": "_",
                    "contributors_count": 0,
                    "commits_count": 0,
                    "commiters_count": 0,
                    "ai_result": -1,
                    "description": description,
                }
            else:
                topics = response.get("topics", [])
                topics_str = "_".join(topics) if isinstance(topics, list) and topics else "_"

                description = response.get("description") or "_"

                self.repo_stats_leak_stats_table = {
                    "size": response.get("size", 0),
                    "stargazers_count": response.get("stargazers_count", 0),
                    "has_issues": response.get("has_issues", False),
                    "has_projects": response.get("has_projects", False),
                    "has_downloads": response.get("has_downloads", False),
                    "has_wiki": response.get("has_wiki", False),
                    "has_pages": response.get("has_pages", False),
                    "forks_count": response.get("forks_count", 0),
                    "open_issues_count": response.get("open_issues_count", 0),
                    "subscribers_count": response.get("subscribers_count", 0),
                    "topics": topics_str,
                    "contributors_count": 0,
                    "commits_count": 0,
                    "commiters_count": 0,
                    "ai_result": -1,
                    "description": description,
                }
        else:
            self._handle_github_error_response(response, "fetch_repository_stats")

        self.repo_stats_getted = True

        # Check if repository is empty (size=0) - mark as inaccessible to skip further stats
        if self.repo_stats_leak_stats_table.get("size", 0) == 0:
            logger.info(f"Repository has zero size, marking as inaccessible: {self.login_repo}")
            self.is_inaccessible = True
            self.inaccessibility_reason = "Репозиторий пустой (размер 0 байт)"
            self.coll_stats_getted = True  # Skip contributors
            self.comm_stats_getted = True  # Skip commits

    def fetch_contributors_stats(self):  # Renamed from get_contributors_stats for better clarity
        # Fast skip: already known empty repo
        if self.repo_stats_leak_stats_table.get("size", 0) == 0:
            self.is_inaccessible = True
            self.inaccessibility_reason = "Репозиторий пустой (размер 0 байт)"
            self.coll_stats_getted = True
            self.comm_stats_getted = True
            return

        if self.is_inaccessible:
            self.coll_stats_getted = True
            return

        if self.type == "Gist":
            self.contributors_stats_accounts_table = [
                {"account": self.login_repo.split("/")[0], "need_monitor": 0, "company_id": 1}
            ]
            self.repo_stats_leak_stats_table["contributors_count"] = 1
            self.coll_stats_getted = True
        else:
            try:
                response_obj = self.request_page(self.contributors_url)

                if response_obj is None:  # Should usually not happen with wait=True
                    self.coll_stats_getted = True
                    return

                if response_obj.status_code == 204:  # No Content (empty repo)
                    response = []
                else:
                    try:
                        response = response_obj.json()
                    except ValueError:  # JSONDecodeError
                        if response_obj.status_code == 200:
                            logger.warning(
                                f"Invalid JSON response from {self.contributors_url}: {response_obj.text[:100]}"
                            )
                        response = {
                            "message": f"Invalid JSON (status {response_obj.status_code})",
                            "status": str(response_obj.status_code),
                        }

            except requests.RequestException as ex:
                logger.error(
                    f"Request Error in getting contributors stats of %s %s %s {self.type}: %s %s %s",
                    self.log_color,
                    self.contributors_url,
                    CLR["RESET"],
                    self.log_color,
                    ex,
                    CLR["RESET"],
                )
                self.coll_stats_getted = True
                return

            if "message" not in response:
                # Check if response is empty list - indicates empty repository
                if isinstance(response, list) and not response:
                    logger.info(f"Repository has no contributors, marking as inaccessible: {self.login_repo}")
                    self.is_inaccessible = True
                    self.inaccessibility_reason = "Репозиторий пустой (нет контрибьюторов)"
                    self.comm_stats_getted = True  # Skip commits too
                elif isinstance(response, list):
                    # Optimized list usage
                    self.contributors_stats_accounts_table = [
                        {"account": contributor["login"], "need_monitor": 0}
                        for contributor in response
                        if isinstance(contributor, dict) and "login" in contributor
                    ]
                    self.repo_stats_leak_stats_table["contributors_count"] = len(self.contributors_stats_accounts_table)
            else:
                self._handle_github_error_response(response, "fetch_contributors_stats")
                # Early exit if marked as inaccessible (empty/deleted/private)
                if self.is_inaccessible:
                    self.comm_stats_getted = True  # Skip commits stats too
            self.coll_stats_getted = True

    def fetch_commits_stats(self):  # Renamed from get_commits_stats for better clarity
        # Fast skip: already known empty repo
        if self.repo_stats_leak_stats_table.get("size", 0) == 0:
            self.is_inaccessible = True
            self.inaccessibility_reason = "Репозиторий пустой (размер 0 байт)"
            self.comm_stats_getted = True
            return

        if self.is_inaccessible:
            self.comm_stats_getted = True
            return

        try:
            response_obj = self.request_page(self.commits_url)

            if response_obj is None:
                self.comm_stats_getted = True
                return

            if response_obj.status_code == 204:
                response = []
            else:
                try:
                    response = response_obj.json()
                except ValueError:
                    if response_obj.status_code == 200:
                        logger.warning(f"Invalid JSON response from {self.commits_url}: {response_obj.text[:100]}")
                    response = {
                        "message": f"Invalid JSON (status {response_obj.status_code})",
                        "status": str(response_obj.status_code),
                    }

        except requests.RequestException as ex:
            logger.error(
                f"Request Error in getting commits stats of %s %s %s {self.type}: %s %s %s",
                self.log_color,
                self.commits_url,
                CLR["RESET"],
                self.log_color,
                ex,
                CLR["RESET"],
            )
            self.comm_stats_getted = True
            return

        if "message" not in response:
            # Check if response is empty list - indicates empty repository
            if isinstance(response, list) and not response:
                logger.info(f"Repository has no commits, marking as inaccessible: {self.login_repo}")
                self.is_inaccessible = True
                self.inaccessibility_reason = "Репозиторий пустой (нет коммитов)"
                self.comm_stats_getted = True
                return

            seen_names = set()
            seen_emails = set()

            for commit_data in response:
                if not isinstance(commit_data, dict):
                    continue

                committer_name = None
                committer_email = None

                if self.type == "Gist":
                    user = commit_data.get("user")
                    if user and "login" in user:
                        committer_name = user["login"]
                        committer_email = "Gist_leak"
                else:
                    commit = commit_data.get("commit")
                    if commit:
                        author = commit.get("author")
                        if author:
                            committer_name = author.get("name")
                            committer_email = author.get("email")

                if committer_name and committer_email:
                    # Check uniqueness
                    is_new = False
                    if self.type == "Gist":
                        if committer_name not in seen_names:
                            is_new = True
                    else:
                        if committer_name not in seen_names and committer_email not in seen_emails:
                            is_new = True

                    if is_new:
                        seen_names.add(committer_name)
                        seen_emails.add(committer_email)

                        monitoring_score = self._calculate_monitoring_score(
                            committer_email, self.login_repo, committer_name
                        )
                        self.commits_stats_commiters_table.append(
                            {
                                "commiter_name": committer_name,
                                "commiter_email": committer_email,
                                "need_monitor": monitoring_score,
                                "related_account_id": 0,
                            }
                        )

            # Update counts after processing
            self.repo_stats_leak_stats_table["commits_count"] = len(response) if isinstance(response, list) else 0
            self.repo_stats_leak_stats_table["commiters_count"] = len(self.commits_stats_commiters_table)
        else:
            self._handle_github_error_response(response, "fetch_commits_stats")
            # Early exit if marked as inaccessible
            if self.is_inaccessible:
                self.comm_stats_getted = True
                return

        self.comm_stats_getted = True

    def set_ai_result(self, ai_result):
        self.repo_stats_leak_stats_table["ai_result"] = ai_result
        self.ai_result = ai_result

    def fetch_repo_stats_leak_stats_table(self):
        return self.repo_stats_leak_stats_table

    # HTTP Session for connection pooling (class-level)
    _session: requests.Session = None

    @classmethod
    def _get_session(cls) -> requests.Session:
        """Get or create HTTP session with connection pooling."""
        if cls._session is None:
            cls._session = requests.Session()
            # Configure connection pool
            adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=20, max_retries=3)
            cls._session.mount("https://", adapter)
            cls._session.mount("http://", adapter)
        return cls._session

    def request_page(self, url, wait_if_no_tokens=True) -> requests.Response:
        """Send API request with rate limiting and connection pooling."""
        token = None
        using_rate_limiter = False

        # Use rate limiter if available
        try:
            from src.github_rate_limiter import get_rate_limiter, is_initialized

            if is_initialized():
                rate_limiter = get_rate_limiter()
                token = rate_limiter.get_best_token()

                if token is None and wait_if_no_tokens:
                    logger.warning("No tokens available, waiting 60s...")
                    time.sleep(60)
                    token = rate_limiter.get_best_token()

                using_rate_limiter = True
        except (RuntimeError, ImportError):
            pass

        # Fallback to old behavior
        if not using_rate_limiter:
            diff = self.rate_limit + self.last_request - time.time()
            if diff > 0.3:
                time.sleep(diff)
            token = next(constants.token_generator())

        if using_rate_limiter and token is None:
            # If we couldn't get a token and weren't supposed to wait (or wait didn't help)
            return None

        headers = {"Authorization": f"Token {token}"} if token else {}
        session = self._get_session()
        response = session.get(url=url, headers=headers, timeout=self.timeout)
        self.last_request = time.time()

        # Update quota from response if using rate limiter (core API)
        if using_rate_limiter and token:
            try:
                rate_limiter.update_quota_from_headers(token, response.headers, resource="core")
                if response.status_code in (403, 429):
                    retry_after = response.headers.get("Retry-After")
                    if retry_after:
                        retry_after = int(retry_after)
                    rate_limiter.handle_rate_limit_error(token, retry_after, resource="core")
            except Exception:
                pass

        return response

    def prepare_stats(self):
        self.fetch_contributors_stats()
        self.fetch_commits_stats()
        logger.info("Prepared stats of %s %s %s ", self.log_color, self.repo_url, CLR["RESET"])
