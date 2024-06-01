# Standart libs import

# Project lib's import
from abc import ABC, abstractmethod

import time
import requests

from src.filters import filter_url_by_db, filter_url_by_repo
from src.logger import logger

from src.searcher.CodeObj import CodeObj
from src.searcher.RepoObj import RepoObj
from src.searcher.CommitObj import CommitObj

from src import constants

# TODO max pages

class GitParser(ABC):
    # attrs to override
    url: str
    T: callable

    # limits
    timeout: int = 1000
    cooldown: float = 60.0
    rate_limit: float = 10.0

    per_page: int = 100

    def __init__(self, dork: str, organization: str, token: str | None = None):
        self.dork: str = dork
        self.organization: str = organization
        self.token: str = token
        self.pages: int = 1
        self.last_request: float = 0.0
        self.params: dict = {}

        self.params['q'] = dork
        self.params['per_page'] = self.per_page

        if self.url is None:
            raise ValueError("Attribute url is not overloaded!")
        if self.T is None:
            raise ValueError("Attribute T is not overloaded!")

    @abstractmethod
    def __str__(self) -> str:
        pass

    def to_obj(self, json_resp):
        return tuple(self.T(repo['html_url'],
                            repo,
                            self.dork.encode().decode('utf-8'),
                            self.organization)
                for repo in json_resp['items']
                if len(filter_url_by_db(repo['html_url'])) == 1
                    and len(filter_url_by_repo(repo['html_url'])) == 1)

    def request_page(self) -> requests.Response:
        return requests.get(
            url=self.url,
            params=self.params,
            headers={'Authorization': f'Token {self.token}'}
                    if self.token else {},
                    timeout=self.timeout)

    def get_pages(self): #-> Generator[tuple[T]]:
        # for page in range(1, self._pages + 1):
        page: int = 1
        while page <= self.pages:
            self.params['page'] = page
            # TODO: проверка наличия в БД 30го "кода", если нет - меняем страницу

            try:
                diff: float = self.rate_limit + self.last_request - time.time()
                if diff > 0.3:
                    time.sleep(diff)

                response = self.request_page()
                self.last_request = time.time()
                logger.info('Github api request performed')
                json_resp = response.json()

            except requests.RequestException as ex:
                logger.info('Request Error in code_scan: %s', ex)
                return

            if response.status_code != 200:
                logger.error('Error status code: %d', response.status_code)
                logger.error('Trying to sleep it off... Cooldown %f sec.',
                                self.cooldown)
                time.sleep(self.cooldown)
                continue

            self.pages = json_resp['total_count']

            yield self.to_obj(json_resp)

            page += 1
            constants.dork_search_counter += 1 # why, 1 dork can have many pages


class GitCodeParser(GitParser):
    url: str = 'https://api.github.com/search/code'
    T = CodeObj

    def __init__(self, dork: str, organization: str, token: str | None = None):
        super().__init__(dork, organization, token)
        self.params['sort'] = 'indexed'
        self.params['order'] = 'desc'

    def __str__(self) -> str:
        return "Code_res"

class GitRepoParser(GitParser):
    url: str = 'https://api.github.com/search/repositories'
    T = RepoObj

    def __init__(self, dork: str, organization: str, token: str | None = None):
        super().__init__(dork, organization, token)
        self.params['sort'] = 'updated'
        self.params['order'] = 'desc'

    def __str__(self) -> str:
        return "Repo_res"

class GitCommitParser(GitParser):
    url: str = 'https://api.github.com/search/commits'
    T = CommitObj

    def __init__(self, dork: str, organization: str, token: str | None = None):
        super().__init__(dork, organization, token)
        self.params['sort'] = 'commiter-date'
        self.params['order'] = 'desc'

    def __str__(self) -> str:
        return "Commit_res"
