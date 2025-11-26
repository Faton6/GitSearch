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
    timeout: int = 1000
    cooldown: float = 60.0
    rate_limit: float = 10.0

    def __init__(self, html_url: str):
        self.login_repo = html_url.split('github.com/')[1]
        self.login_repo = self.login_repo.split('/')[0] + '/' + self.login_repo.split('/')[1]
        if 'gist.github.com' in html_url:
            self.type = 'Gist'
            self.repo_url: str = 'https://api.github.com/gists/' + self.login_repo.split('/')[1]
            self.commits_url: str = self.repo_url + '/commits'
        else:
            self.type = 'Repository'
            self.repo_url: str = 'https://api.github.com/repos/' + self.login_repo
            self.contributors_url: str = self.repo_url + '/contributors'
            self.commits_url: str = self.repo_url + '/commits'
        self.last_request: float = 0.0
        self.log_color = choice(tuple(CLR.values()))
        self.created_at = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        self.updated_at = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        self.repo_stats_leak_stats_table: dict = {'size': 0,
                                                  'stargazers_count': 0,
                                                  'has_issues': 0,
                                                  'has_projects': 0,
                                                  'has_downloads': 0,
                                                  'has_wiki': 0, 'has_pages': 0,
                                                  'forks_count': 0,
                                                  'open_issues_count': 0,
                                                  'subscribers_count': 0,
                                                  'topics': '_',
                                                  'contributors_count': 0,
                                                  'commits_count': 0,
                                                  'commiters_count': 0,
                                                  'ai_result': -1, # 1 - ai found leak, 0 - ai not found leak, -1 - ai not used
                                                  'description': '_'
                                                  }

        self.contributors_stats_accounts_table: list = []

        self.commits_stats_commiters_table: list = []
        
        self.ai_result = -1 # 1 - ai found leak, 0 - ai not found leak, -1 - ai not used
        
        self.repo_stats_getted = False
        self.coll_stats_getted = False
        self.comm_stats_getted = False
        
        self.is_inaccessible = False
        self.inaccessibility_reason = ""

        if self.login_repo is None:
            raise ValueError("Attribute url is not overloaded!")

    def _is_corporate_domain(self, email: str) -> bool:
        """Check if email domain is corporate (not a public provider)."""
        if not email or '@' not in email:
            return False
            
        domain = email.split('@')[-1].lower()
        return domain not in constants.PUBLIC_EMAIL_DOMAINS
    
    def _contains_dangerous_patterns(self, repo_name: str, committer_name: str = "") -> bool:
        """Check if repository or committer info contains dangerous patterns with word boundaries."""
        text_to_check = f"{repo_name} {committer_name}".lower()
        # Use word boundaries to reduce false positives
        for pattern in constants.DANGEROUS_PATTERNS:
            if re.search(r'\b' + re.escape(pattern) + r'\b', text_to_check):
                return True
        return False
    
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
        if not isinstance(response, dict) or 'message' not in response:
            return False
        
        status = response.get('status', '')
        message = response.get('message', '')
        
        if status == '409' and 'empty' in message.lower():
            logger.info(f'Repository is empty ({context}): {self.login_repo}')
            self.is_inaccessible = True
            self.inaccessibility_reason = 'Репозиторий пустой (нет коммитов)'
            return True
        elif status == '404':
            logger.warning(f'Resource not found ({context}): {self.login_repo}')
            self.is_inaccessible = True
            self.inaccessibility_reason = 'Репозиторий не найден (удален или приватный)'
            return True
        elif status == '403':
            logger.warning(f'Access forbidden ({context}): {self.login_repo}')
            self.is_inaccessible = True
            self.inaccessibility_reason = 'Доступ к репозиторию запрещен'
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
            
            owner, name = self.login_repo.split('/')
            variables = {'owner': owner, 'name': name}
            
            data = graphql_client.execute_query(query, variables)
            
            if data and 'data' in data and data['data'] and 'repository' in data['data']:
                repo = data['data']['repository']
                
                # Parse timestamps
                self.created_at = time.strftime('%Y-%m-%d %H:%M:%S',
                    time.strptime(repo['createdAt'], '%Y-%m-%dT%H:%M:%SZ'))
                self.updated_at = time.strftime('%Y-%m-%d %H:%M:%S',
                    time.strptime(repo['updatedAt'], '%Y-%m-%dT%H:%M:%SZ'))
                
                # Import safe helpers from utils
                from src.utils import safe_get_count, safe_get_nested
                
                # Безопасное извлечение topics
                topics_value = '_'
                repo_topics = repo.get('repositoryTopics')
                if isinstance(repo_topics, dict):
                    nodes = repo_topics.get('nodes', [])
                    if isinstance(nodes, list):
                        topics_value = ','.join([t['topic']['name'] for t in nodes if isinstance(t, dict) and 'topic' in t and 'name' in t.get('topic', {})]) or '_'
                
                self.repo_stats_leak_stats_table = {
                    'size': repo.get('diskUsage', 0),
                    'stargazers_count': repo.get('stargazerCount', 0),
                    'has_issues': 1 if repo.get('hasIssuesEnabled') else 0,
                    'has_projects': 1 if repo.get('hasProjectsEnabled') else 0,
                    'has_downloads': 0,
                    'has_wiki': 1 if repo.get('hasWikiEnabled') else 0,
                    'has_pages': 0,
                    'forks_count': repo.get('forkCount', 0),
                    'open_issues_count': safe_get_count(repo, 'issues', 0),
                    'subscribers_count': safe_get_count(repo, 'watchers', 0),
                    'topics': topics_value,
                    'contributors_count': 0,
                    'commits_count': safe_get_nested(repo, 'defaultBranchRef', 'target', 'history', 'totalCount', default=0),
                    'commiters_count': 0,
                    'ai_result': -1,
                    'description': repo.get('description', '_') or '_'
                }
                
                self.repo_stats_getted = True
                logger.debug(f'Fetched stats via GraphQL for {self.login_repo}')
                return True
            elif data and 'errors' in data:
                logger.debug(f'GraphQL query returned errors: {data["errors"]}')
        except Exception as e:
            logger.debug(f'GraphQL stats fetch failed: {e}')
        
        return False
    
    # check repository stats:
    def fetch_repository_stats(self):  # Renamed from get_repo_stats for better clarity
        if self.type == 'Repository' and not self.repo_stats_getted:
            try:
                from src.searcher.graphql_client import get_graphql_client
                graphql_client = get_graphql_client()
                if not graphql_client._graphql_disabled:
                    if self._fetch_stats_via_graphql():
                        return
            except (ImportError, RuntimeError, Exception) as e:
                logger.debug(f'GraphQL client initialization failed: {e}')
        
        # Use rate limiter if available
        try:
            from src.github_rate_limiter import get_rate_limiter, is_initialized
            if is_initialized():
                rate_limiter = get_rate_limiter()
                token = rate_limiter.get_best_token()
                if token is None:
                    logger.warning("No tokens available for stats, waiting...")
                    time.sleep(60)
                    token = rate_limiter.get_best_token()
            else:
                raise ImportError()
        except (RuntimeError, ImportError):
            # Fallback to old rate limiting
            diff: float = self.rate_limit + self.last_request - time.time()
            if diff > 0.3:
                time.sleep(diff)
            token = next(constants.token_generator())
        
        try:
            headers = {'Authorization': f'Token {token}'} if token else {}
            api_response = requests.get(self.repo_url, headers=headers, timeout=self.timeout)
            self.last_request = time.time()
            
            # Update rate limit if using rate limiter (core API)
            try:
                from src.github_rate_limiter import get_rate_limiter, is_initialized
                if is_initialized():
                    rate_limiter = get_rate_limiter()
                    rate_limiter.update_quota_from_headers(token, api_response.headers, resource='core')
                    if api_response.status_code in (403, 429):
                        retry_after = api_response.headers.get('Retry-After')
                        if retry_after:
                            retry_after = int(retry_after)
                        rate_limiter.handle_rate_limit_error(token, retry_after, resource='core')
            except (RuntimeError, ImportError):
                pass
            
            response = api_response.json()
            #logger.info(f'Performed Github api request to {self.type} stats of %s %s %s {self.type}',
            #            self.log_color, self.repo_url, CLR["RESET"])
        except requests.RequestException as ex:
            logger.error(f'Request Error in getting {self.type} stats of %s %s %s {self.type}: %s %s %s',
                         self.log_color, self.repo_url, CLR["RESET"], self.log_color, ex,
                         CLR["RESET"])
        else:
            if type(response) is dict and 'message' not in response:
                self.created_at = time.strftime('%Y-%m-%d %H:%M:%S',
                                                time.strptime(response['created_at'], '%Y-%m-%dT%H:%M:%SZ'))
                self.updated_at = time.strftime('%Y-%m-%d %H:%M:%S',
                                                time.strptime(response['updated_at'], '%Y-%m-%dT%H:%M:%SZ'))

                if self.type == 'Gist':
                    full_size = 0
                    if 'files' in response:
                        files_data = response['files']
                        if isinstance(files_data, dict):
                            for file_name in files_data.keys():
                                file_info = files_data[file_name]
                                if isinstance(file_info, dict) and 'size' in file_info:
                                    full_size += file_info['size']
                                else:
                                    logger.warning(f"Unexpected file_info structure for {file_name}: {type(file_info)}")
                        else:
                            logger.warning(f"Unexpected files structure: {type(files_data)}")
                    
                    # Handle forks - can be a list or not present
                    forks_count = 0
                    if 'forks' in response:
                        if isinstance(response['forks'], list):
                            forks_count = len(response['forks'])
                        elif isinstance(response['forks'], int):
                            forks_count = response['forks']
                    
                    # Handle description - can be None
                    description = response.get('description', '_')
                    if description is None:
                        description = '_'
                    
                    self.repo_stats_leak_stats_table = {'size': full_size,
                                                        'stargazers_count': 0,
                                                        'has_issues': 0,
                                                        'has_projects': 0,
                                                        'has_downloads': 0,
                                                        'has_wiki': 0,
                                                        'has_pages': 0,
                                                        'forks_count': forks_count,
                                                        'open_issues_count': 0,
                                                        'subscribers_count': 0,
                                                        'topics': '_',
                                                        'contributors_count': 0,
                                                        'commits_count': 0,
                                                        'commiters_count': 0,
                                                        'ai_result': -1, # 1 - ai found leak, 0 - ai not found leak, -1 - ai not used
                                                        'description': description
                                                        }
                else:
                    # Handle topics - can be a list or not present
                    topics = response.get('topics', [])
                    if isinstance(topics, list):
                        topics_str = '_'.join(topics) if topics else '_'
                    else:
                        topics_str = '_'
                    
                    # Handle description - can be None
                    description = response.get('description', '_')
                    if description is None:
                        description = '_'
                    
                    self.repo_stats_leak_stats_table = {'size': response.get('size', 0),
                                                        'stargazers_count': response.get('stargazers_count', 0),
                                                        'has_issues': response.get('has_issues', False),
                                                        'has_projects': response.get('has_projects', False),
                                                        'has_downloads': response.get('has_downloads', False),
                                                        'has_wiki': response.get('has_wiki', False),
                                                        'has_pages': response.get('has_pages', False),
                                                        'forks_count': response.get('forks_count', 0),
                                                        'open_issues_count': response.get('open_issues_count', 0),
                                                        'subscribers_count': response.get('subscribers_count', 0),
                                                        'topics': topics_str,
                                                        'contributors_count': 0,
                                                        'commits_count': 0,
                                                        'commiters_count': 0,
                                                        'ai_result': -1, # 1 - ai found leak, 0 - ai not found leak, -1 - ai not used
                                                        'description': description
                                                        }
            else:
                self._handle_github_error_response(response, 'fetch_repository_stats')
        self.repo_stats_getted = True

    def fetch_contributors_stats(self):  # Renamed from get_contributors_stats for better clarity
        if self.type == 'Gist':
            self.contributors_stats_accounts_table = [{'account': self.login_repo.split('/')[0],
                                                       'need_monitor': 0,
                                                       'company_id': 1
                                                       }]
            self.repo_stats_leak_stats_table['contributors_count'] = 1
            self.coll_stats_getted = True
        else:
            diff: float = self.rate_limit + self.last_request - time.time()
            if diff > 0.3:
                time.sleep(diff)
            try:
                response = self.request_page(self.contributors_url).json()
                self.last_request = time.time()
                #logger.info(f'Performed Github api request to {self.type} contributors of %s %s %s ',
                #            self.log_color, self.contributors_url, CLR["RESET"])
            except requests.RequestException as ex:
                logger.error(f'Request Error in getting contributors stats of %s %s %s {self.type}: %s %s %s',
                             self.log_color, self.contributors_url, CLR["RESET"], self.log_color, ex,
                             CLR["RESET"])
            else:
                if 'message' not in response:
                    for contributor in response:
                        if type(contributor) is dict and 'login' in contributor.keys():
                            self.contributors_stats_accounts_table.append({'account': contributor['login'],
                                                                           'need_monitor': 0
                                                                           })
                else:
                    self._handle_github_error_response(response, 'fetch_contributors_stats')
                    self.repo_stats_leak_stats_table['contributors_count'] = len(self.contributors_stats_accounts_table)
            self.coll_stats_getted = True

    def fetch_commits_stats(self):  # Renamed from get_commits_stats for better clarity
        diff: float = self.rate_limit + self.last_request - time.time()
        if diff > 0.3:
            time.sleep(diff)
        try:
            response = self.request_page(self.commits_url).json()
            self.last_request = time.time()

            #logger.info(f'Performed Github api request to {self.type} commits of %s %s %s ',
            #            self.log_color, self.commits_url, CLR["RESET"])
        except requests.RequestException as ex:
            logger.error(f'Request Error in getting commits stats of %s %s %s {self.type}: %s %s %s',
                         self.log_color, self.commits_url, CLR["RESET"], self.log_color, ex,
                         CLR["RESET"])
        else:
            if 'message' not in response:
                list_uniq_names = []
                list_uniq_emails = []
                if self.type == 'Gist':
                    for commits in response:
                        if isinstance(commits, dict) and 'user' in commits.keys() and 'login' in commits['user'].keys():
                            if commits['user']['login'] in list_uniq_names :
                                pass
                            else:
                                list_uniq_names.append(commits['user']['login'])
                                # Calculate monitoring score based on corporate domain and dangerous patterns
                                monitoring_score = self._calculate_monitoring_score(
                                    'Gist_leak', self.login_repo, commits['user']['login']
                                )
                                self.commits_stats_commiters_table.append({'commiter_name': commits['user']['login'],
                                                                           'commiter_email': 'Gist_leak',
                                                                           'need_monitor': monitoring_score,
                                                                           'related_account_id': 0
                                                                           })
                else:
                    for commits in response:
                        if 'commit' in commits.keys() and 'author' in commits['commit'].keys():
                            if commits['commit']['author']['name'] in list_uniq_names \
                                    or commits['commit']['author']['email'] in list_uniq_emails:
                                pass
                            else:
                                list_uniq_names.append(commits['commit']['author']['name'])
                                list_uniq_emails.append(commits['commit']['author']['email'])
                                # Calculate monitoring score based on corporate domain and dangerous patterns
                                monitoring_score = self._calculate_monitoring_score(
                                    commits['commit']['author']['email'], 
                                    self.login_repo, 
                                    commits['commit']['author']['name']
                                )
                                self.commits_stats_commiters_table.append({'commiter_name': commits['commit']['author'][
                                    'name'],
                                                                           'commiter_email': commits['commit']['author'][
                                                                               'email'],
                                                                           'need_monitor': monitoring_score,
                                                                           'related_account_id': 0
                                                                           })
            else:
                self._handle_github_error_response(response, 'fetch_commits_stats')
                self.repo_stats_leak_stats_table['commits_count'] = len(response) if isinstance(response, list) else 0
                self.repo_stats_leak_stats_table['commiters_count'] = len(self.commits_stats_commiters_table)

        self.comm_stats_getted = True

    def set_ai_result(self, ai_result):
        self.repo_stats_leak_stats_table['ai_result'] = ai_result
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
            adapter = requests.adapters.HTTPAdapter(
                pool_connections=10,
                pool_maxsize=20,
                max_retries=3
            )
            cls._session.mount('https://', adapter)
            cls._session.mount('http://', adapter)
        return cls._session
    
    def request_page(self, url) -> requests.Response:
        """Send API request with rate limiting and connection pooling."""
        # Use rate limiter if available
        try:
            from src.github_rate_limiter import get_rate_limiter, is_initialized
            if is_initialized():
                rate_limiter = get_rate_limiter()
                token = rate_limiter.get_best_token()
                if token is None:
                    logger.warning("No tokens available, waiting 60s...")
                    time.sleep(60)
                    token = rate_limiter.get_best_token()
            else:
                raise ImportError()
        except (RuntimeError, ImportError):
            # Fallback to old behavior
            token = next(constants.token_generator())
        
        headers = {'Authorization': f'Token {token}'} if token else {}
        session = self._get_session()
        response = session.get(url=url, headers=headers, timeout=self.timeout)
        
        # Update quota from response if using rate limiter (core API)
        try:
            from src.github_rate_limiter import get_rate_limiter, is_initialized
            if is_initialized():
                rate_limiter = get_rate_limiter()
                rate_limiter.update_quota_from_headers(token, response.headers, resource='core')
                if response.status_code in (403, 429):
                    retry_after = response.headers.get('Retry-After')
                    if retry_after:
                        retry_after = int(retry_after)
                    rate_limiter.handle_rate_limit_error(token, retry_after, resource='core')
        except (RuntimeError, ImportError):
            pass
        
        return response

    def prepare_stats(self):
        self.fetch_contributors_stats()
        self.fetch_commits_stats()
        logger.info(f'Prepared stats of %s %s %s ', self.log_color, self.repo_url, CLR["RESET"])
