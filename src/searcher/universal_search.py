"""Universal GitHub Search Client with REST and GraphQL support."""

import time
import requests
from typing import Dict, List, Any, Optional, Generator
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
            SearchType.ISSUES: f"{base_url}/issues"
        }.get(self.search_type)
        
        self.graphql_queries = {
            SearchType.REPOSITORIES: """
                query SearchRepos($query: String!, $first: Int!, $after: String) {
                  search(query: $query, type: REPOSITORY, first: $first, after: $after) {
                    repositoryCount
                    pageInfo { hasNextPage endCursor }
                    nodes {
                      ... on Repository {
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
                        repositoryTopics(first: 10) {
                          nodes { topic { name } }
                        }
                        defaultBranchRef {
                          target {
                            ... on Commit {
                              history { totalCount }
                              author { name email user { login } }
                            }
                          }
                        }
                        collaborators { totalCount }
                      }
                    }
                  }
                  rateLimit { limit remaining resetAt cost }
                }
            """,
            SearchType.CODE: """
                query SearchCode($query: String!, $first: Int!, $after: String) {
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
        }
    
    def _get_token(self) -> Optional[str]:
        try:
            from src.github_rate_limiter import get_rate_limiter
            rate_limiter = get_rate_limiter()
            
            # Wait for rate limit
            if self.search_type in (SearchType.REPOSITORIES, SearchType.CODE, SearchType.COMMITS):
                rate_limiter.wait_for_search_rate_limit()
            
            token = rate_limiter.get_best_token()
            if token is None:
                logger.warning("No tokens available, waiting 60s...")
                time.sleep(60)
                token = rate_limiter.get_best_token()
            
            return token
        except (RuntimeError, ImportError):
            # Fallback
            return next(constants.token_generator())
    
    def _update_rate_limit(self, token: str, headers: Dict[str, str]):
        try:
            from src.github_rate_limiter import get_rate_limiter
            rate_limiter = get_rate_limiter()
            rate_limiter.update_quota_from_headers(token, headers)
            
            if int(headers.get('X-RateLimit-Remaining', 5000)) < 100:
                logger.warning(
                    f"Low quota: {headers.get('X-RateLimit-Remaining')}/{headers.get('X-RateLimit-Limit')}"
                )
        except (RuntimeError, ImportError):
            pass
    
    def _handle_rate_limit_error(self, token: str, response: requests.Response):
        try:
            from src.github_rate_limiter import get_rate_limiter
            rate_limiter = get_rate_limiter()
            
            retry_after = response.headers.get('Retry-After')
            if retry_after:
                retry_after = int(retry_after)
            rate_limiter.handle_rate_limit_error(token, retry_after)
        except (RuntimeError, ImportError):
            # Fallback
            retry_after = int(response.headers.get('Retry-After', 60))
            logger.warning(f"Rate limit hit, waiting {retry_after}s")
            time.sleep(retry_after)
    
    def _search_graphql(self, query: str, max_results: int = 100) -> List[Dict]:
        if self.search_type not in self.graphql_queries:
            return []
        
        try:
            from src.searcher.graphql_client import get_graphql_client
            graphql_client = get_graphql_client()
            
            results = []
            has_next_page = True
            cursor = None
            
            graphql_query = self.graphql_queries[self.search_type]
            
            while has_next_page and len(results) < max_results:
                variables = {
                    'query': query,
                    'first': min(100, max_results - len(results)),
                    'after': cursor
                }
                
                data = graphql_client.execute_query(graphql_query, variables)
                
                if not data or 'data' not in data or not data['data']:
                    break
                
                search_data = data['data'].get('search', {})
                nodes = search_data.get('nodes', [])
                
                # Convert to unified format
                for node in nodes:
                    if node:
                        converted = self._convert_graphql_to_rest(node)
                        if converted:
                            results.append(converted)
                
                page_info = search_data.get('pageInfo', {})
                has_next_page = page_info.get('hasNextPage', False)
                cursor = page_info.get('endCursor')
                
                logger.debug(f"GraphQL retrieved {len(results)} results")
            
            return results
            
        except Exception as e:
            logger.warning(f"GraphQL search failed: {e}")
            return []
    
    def _convert_graphql_to_rest(self, node: Dict) -> Optional[Dict]:
        try:
            if self.search_type == SearchType.REPOSITORIES:
                return {
                    'name': node.get('name'),
                    'full_name': f"{node['owner']['login']}/{node['name']}",
                    'owner': {'login': node['owner']['login']},
                    'html_url': node.get('url'),
                    'private': node.get('isPrivate', False),
                    'created_at': node.get('createdAt'),
                    'updated_at': node.get('updatedAt'),
                    'pushed_at': node.get('pushedAt'),
                    'description': node.get('description'),
                    'stargazers_count': node.get('stargazerCount', 0),
                    'forks_count': node.get('forkCount', 0),
                    'watchers_count': node.get('watchers', {}).get('totalCount', 0),
                    'open_issues_count': node.get('issues', {}).get('totalCount', 0),
                    'has_issues': node.get('hasIssuesEnabled', False),
                    'has_projects': node.get('hasProjectsEnabled', False),
                    'has_wiki': node.get('hasWikiEnabled', False),
                    'has_downloads': False,
                    'size': node.get('diskUsage', 0),
                    'language': node.get('primaryLanguage', {}).get('name') if node.get('primaryLanguage') else None,
                    'topics': [t['topic']['name'] for t in node.get('repositoryTopics', {}).get('nodes', [])],
                    'collaborators_count': node.get('collaborators', {}).get('totalCount', 0),
                    'commit_count': node.get('defaultBranchRef', {}).get('target', {}).get('history', {}).get('totalCount', 0),
                }
            
            elif self.search_type == SearchType.CODE:
                repo = node.get('repository', {})
                return {
                    'name': node.get('path', '').split('/')[-1],
                    'path': node.get('path'),
                    'html_url': f"{repo.get('url')}/blob/master/{node.get('path')}",
                    'repository': {
                        'name': repo.get('name'),
                        'full_name': f"{repo['owner']['login']}/{repo['name']}",
                        'owner': {'login': repo['owner']['login']},
                        'html_url': repo.get('url'),
                        'private': repo.get('isPrivate', False),
                        'description': repo.get('description'),
                        'size': repo.get('diskUsage', 0),
                    }
                }
            
            return None
            
        except Exception as e:
            logger.error(f"Error converting GraphQL result: {e}")
            return None
    
    def _search_rest(self, query: str, max_results: int = 100, per_page: int = 100) -> Generator[List[Dict], None, None]:
        page = 1
        max_pages = ceil(min(max_results, 1000) / per_page)
        consecutive_errors = 0
        max_errors = 5
        
        while page <= max_pages:
            token = self._get_token()
            headers = {'Authorization': f'Token {token}'} if token else {}
            
            if self.search_type == SearchType.GISTS:
                url = self.rest_endpoint
                params = {'per_page': per_page, 'page': page}
            else:
                url = self.rest_endpoint
                params = {
                    'q': query,
                    'per_page': per_page,
                    'page': page,
                    'sort': 'updated',
                    'order': 'desc'
                }
            
            try:
                response = requests.get(
                    url,
                    params=params,
                    headers=headers,
                    timeout=constants.MAX_TIME_TO_SEARCH_GITHUB_REQUEST
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
                                item for item in items
                                if (item.get('description') and query.lower() in item.get('description').lower())
                                or any(query.lower() in f.lower() for f in item.get('files', {}).keys())
                            ]
                    else:
                        items = data.get('items', [])
                    
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
                    wait_time = min(2 ** consecutive_errors, 300)
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
                time.sleep(min(2 ** consecutive_errors, 60))
                if consecutive_errors >= max_errors:
                    break
    
    def search(self, query: str, max_results: int = 100) -> Generator[List[Dict], None, None]:
        if self.search_type == SearchType.GISTS:
            logger.info(f"Using REST API for {self.search_type.value}: {query}")
            yield from self._search_rest(query, max_results)
            return
        
        graphql_available = False
        if self.use_graphql and self.search_type in self.graphql_queries:
            try:
                from src.searcher.graphql_client import get_graphql_client
                graphql_client = get_graphql_client()
                graphql_available = not graphql_client._graphql_disabled
            except:
                pass
        
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
