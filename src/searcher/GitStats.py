import requests
import time
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
        self.repo_url: str = 'https://api.github.com/repos/' + self.login_repo
        self.contributors_url: str = 'https://api.github.com/repos/' + self.login_repo + '/contributors'
        self.commits_url: str = 'https://api.github.com/repos/' + self.login_repo + '/commits'
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
                                                  'description': '_'
                                                  }

        self.contributors_stats_accounts_table: list = []

        self.commits_stats_commiters_table: list = []

        self.repo_stats_getted = False
        self.coll_stats_getted = False
        self.comm_stats_getted = False

        if self.login_repo is None:
            raise ValueError("Attribute url is not overloaded!")

    # check repository stats:
    def get_repo_stats(self):
        diff: float = self.rate_limit + self.last_request - time.time()
        if diff > 0.3:
            time.sleep(diff)
        try:
            response = self.request_page(self.repo_url).json()
            self.last_request = time.time()
            logger.info('Performed Github api request to repository stats of %s %s %s repository',
                        self.log_color, 'https://github.com/' + self.login_repo, CLR["RESET"])
        except requests.RequestException as ex:
            logger.error('Request Error in getting repository stats of %s %s %s repository: %s %s %s',
                         self.log_color, 'https://github.com/' + self.login_repo, CLR["RESET"], self.log_color, ex,
                         CLR["RESET"])
        else:
            if 'message' not in response:
                self.created_at = time.strftime('%Y-%m-%d %H:%M:%S',
                                                time.strptime(response['created_at'], '%Y-%m-%dT%H:%M:%SZ'))
                self.updated_at = time.strftime('%Y-%m-%d %H:%M:%S',
                                                time.strptime(response['updated_at'], '%Y-%m-%dT%H:%M:%SZ'))

                self.repo_stats_leak_stats_table = {'size': response['size'],
                                                    'stargazers_count': response['stargazers_count'],
                                                    'has_issues': response['has_issues'],
                                                    'has_projects': response['has_projects'],
                                                    'has_downloads': response['has_downloads'],
                                                    'has_wiki': response['has_wiki'],
                                                    'has_pages': response['has_pages'],
                                                    'forks_count': response['forks_count'],
                                                    'open_issues_count': response['open_issues_count'],
                                                    'subscribers_count': response['subscribers_count'],
                                                    'topics': '_'.join(response['topics']),
                                                    'contributors_count': 0,
                                                    'commits_count': 0,
                                                    'commiters_count': 0,
                                                    'description': response['description']
                                                    }
            else:
                logger.error('Got message from github request: %s %s %s', self.log_color,
                             str(response), CLR["RESET"])

        self.repo_stats_getted = True

    def get_contributors_stats(self):
        diff: float = self.rate_limit + self.last_request - time.time()
        if diff > 0.3:
            time.sleep(diff)
        try:
            response = self.request_page(self.contributors_url).json()
            self.last_request = time.time()
            logger.info('Performed Github api request to contributors of %s %s %s repository',
                        self.log_color, 'https://github.com/' + self.login_repo, CLR["RESET"])
        except requests.RequestException as ex:
            logger.error('Request Error in getting contributors stats of %s %s %s repository: %s %s %s',
                         self.log_color, 'https://github.com/' + self.login_repo, CLR["RESET"], self.log_color, ex,
                         CLR["RESET"])
        else:
            if 'message' not in response:
                for contributor in response:
                    if 'login' in contributor.keys():
                        self.contributors_stats_accounts_table.append({'account': contributor['login'],
                                                                       'need_monitor': 0,
                                                                       'related_company_id': 0
                                                                       })
            else:
                logger.error('Got message from github request: %s %s %s', self.log_color,
                             str(response), CLR["RESET"])
                self.repo_stats_leak_stats_table['contributors_count'] = len(self.contributors_stats_accounts_table)
        self.coll_stats_getted = True

    def get_commits_stats(self):
        diff: float = self.rate_limit + self.last_request - time.time()
        if diff > 0.3:
            time.sleep(diff)
        try:
            response = self.request_page(self.commits_url).json()
            self.last_request = time.time()

            logger.info('Performed Github api request to commits of %s %s %s repository',
                        self.log_color, 'https://github.com/' + self.login_repo, CLR["RESET"])
        except requests.RequestException as ex:
            logger.error('Request Error in getting commits stats of %s %s %s repository: %s %s %s',
                         self.log_color, 'https://github.com/' + self.login_repo, CLR["RESET"], self.log_color, ex,
                         CLR["RESET"])
        else:
            if 'message' not in response:
                list_uniq_names = []
                list_uniq_emails = []
                for commits in response:
                    if 'commit' in commits.keys() and 'author' in commits['commit'].keys():
                        if commits['commit']['author']['name'] in list_uniq_names \
                                or commits['commit']['author']['email'] in list_uniq_emails:
                            pass
                        else:
                            list_uniq_names.append(commits['commit']['author']['name'])
                            list_uniq_emails.append(commits['commit']['author']['email'])
                            self.commits_stats_commiters_table.append({'commiter_name': commits['commit']['author'][
                                'name'],
                                                                       'commiter_email': commits['commit']['author'][
                                                                           'email'],
                                                                       # TODO: check if it non-popular domain
                                                                       'need_monitor': 0,
                                                                       # TODO: update to 1 if it dangerous leak
                                                                       'related_account_id': 0
                                                                       })
            else:
                logger.error('Got message from github request: %s %s %s', self.log_color,
                             str(response), CLR["RESET"])
                self.repo_stats_leak_stats_table['commits_count'] = len(response)
                self.repo_stats_leak_stats_table['commiters_count'] = len(self.commits_stats_commiters_table)

        self.comm_stats_getted = True

    def request_page(self, url) -> requests.Response:
        token = next(constants.token_generator())
        return requests.get(
            url=url,
            headers={'Authorization': f'Token {token}'}
            if token else {},
            timeout=self.timeout)

    def prepare_stats(self):
        self.get_contributors_stats()
        self.get_commits_stats()
