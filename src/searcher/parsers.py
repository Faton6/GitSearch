# Standart libs import
from abc import ABC, abstractmethod
import time
import requests
from math import ceil

# Project lib's import

from src.filters import filter_url_by_db, filter_url_by_repo
from src.logger import logger

from src.LeakObj import CodeObj, RepoObj, CommitObj

from src import constants


# TODO max pages

class GitParserSearch(ABC):
    # attrs to override
    url: str
    T: callable

    # limits
    timeout: int = 1000
    cooldown: float = 60.0
    rate_limit: float = 10.0
    repo_count_limit: int = 1000  # Github api restriction https://docs.github.com/rest/search/search#search-code
    per_page: int = 100

    def __init__(self, dork: str, organization: int):
        self.dork: str = dork
        self.organization: int = organization
        self.pages: int = 1
        self.last_request: float = 0.0
        self.params: dict = {'q': dork, 'per_page': self.per_page}

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
                     if len(filter_url_by_db(repo['html_url'])) == 1  # debug if len(filter_url_by_db(repo['login_repo']))
                     and len(filter_url_by_repo(repo['html_url'])) == 1
                     )

    def request_page(self) -> requests.Response:
        token = next(constants.token_generator())
        return requests.get(
            url=self.url,
            params=self.params,
            headers={'Authorization': f'Token {token}'}
            if token else {},
            timeout=self.timeout)

    def get_pages(self):  # -> Generator[tuple[T]]:
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
                logger.info('Github api Search request performed')
                json_resp = response.json()

            except requests.RequestException as ex:
                logger.error('Request Error in code_scan: %s', ex)
                return

            if response.status_code != 200:
                logger.error('Error status code: %d', response.status_code)
                logger.error('Error info: %s', response.text)
                logger.error('Trying to sleep it off... Cooldown %f sec.',
                             self.cooldown)
                time.sleep(self.cooldown)
                continue

            self.pages = ceil(min(json_resp['total_count'], self.repo_count_limit) / self.per_page)
            yield self.to_obj(json_resp)

            page += 1
            constants.dork_search_counter += 1  # why, 1 dork can have many pages


class GitCodeParser(GitParserSearch):
    url: str = 'https://api.github.com/search/code'
    T = CodeObj

    def __init__(self, dork: str, organization: int):
        super().__init__(dork, organization)
        self.params['sort'] = 'indexed'
        self.params['order'] = 'desc'

    def __str__(self) -> str:
        return "GitCodeParser"


class GitRepoParser(GitParserSearch):
    url: str = 'https://api.github.com/search/repositories'
    T = RepoObj

    def __init__(self, dork: str, organization: int):
        super().__init__(dork, organization)
        self.params['sort'] = 'updated'
        self.params['order'] = 'desc'

    def __str__(self) -> str:
        return "GitRepoParser"


class GitCommitParser(GitParserSearch):
    url: str = 'https://api.github.com/search/commits'
    T = CommitObj

    def __init__(self, dork: str, organization: int):
        super().__init__(dork, organization)
        self.params['sort'] = 'commiter-date'
        self.params['order'] = 'desc'

    def __str__(self) -> str:
        return "GitCommitParser"


