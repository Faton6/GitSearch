import requests
import time

from src.logger import logger


class GitParserStats:
    # attrs to override
    url: str

    # limits
    timeout: int = 1000
    cooldown: float = 60.0
    rate_limit: float = 10.0

    def __init__(self, html_url: str, token: str | None = None):
        html_url = html_url.split('github.com/')[1]
        html_url = html_url.split('/')[0] + '/' + html_url.split('/')[1]
        self.url: str = 'https://api.github.com/repos/' + html_url
        self.token: str = token
        self.last_request: float = 0.0

        if self.url is None:
            raise ValueError("Attribute url is not overloaded!")

    # check repository stats:
    def get_stats(self):
        diff: float = self.rate_limit + self.last_request - time.time()
        if diff > 0.3:
            time.sleep(diff)
        response = self.request_page()
        self.last_request = time.time()
        logger.info('Github api request to repository performed')
        try:
            json_resp = response.json()
        except requests.RequestException as ex:
            logger.info('Request Error in getting stats: %s', ex)
            json_resp = {'size': 0}
            return
        if 'message' in json_resp:
            json_resp = {'size': 0}
        else:
            json_resp = {'size': json_resp['size'], 'stargazers_count': json_resp['stargazers_count'],
                         'watchers_count': json_resp['watchers_count'], 'has_issues': json_resp['has_issues'],
                         'has_projects': json_resp['has_projects'], 'has_downloads': json_resp['has_downloads'],
                         'has_wiki': json_resp['has_wiki'], 'has_pages': json_resp['has_pages'],
                         'forks_count': json_resp['forks_count'], 'open_issues_count': json_resp['open_issues_count'],
                         'subscribers_count': json_resp['subscribers_count'], 'topics': '_'.join(json_resp['topics'])}
        '''
        {json_resp['size'], json_resp['stargazers_count'],
                     json_resp['watchers_count'], json_resp['has_issues'],
                     json_resp['has_projects'], json_resp['has_downloads'],
                     json_resp['has_wiki'], json_resp['has_pages'],
                     json_resp['forks_count'], json_resp['open_issues_count'],
                     json_resp['subscribers_count'], '_'.join(json_resp['topics'])}
        '''

        return json_resp

    def request_page(self) -> requests.Response:
        return requests.get(
            url=self.url,
            headers={'Authorization': f'Token {self.token}'}
            if self.token else {},
            timeout=self.timeout)
