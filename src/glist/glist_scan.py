# Standart libs import
import re
import requests
from bs4 import BeautifulSoup
import time
from urllib.parse import unquote

# Project lib's import
from src.logger import logger, CLR
from src import constants
from src.LeakObj import GlistObj
from src import filters

GIST_LINK_HTML_CLASS = 'link-overlay'


def _exc_catcher(func):
    def wrapper(*args, **kwargs):
        try:
            res = func(*args, **kwargs)
        except Exception as exc:
            logger.error(
                f'Error during glist scan in {func.__name__}(): {exc}')
        else:
            return res

    return wrapper


class GlistScan:
    @classmethod
    @_exc_catcher
    def _glist_request(cls,
                       dork,
                       filter_: str = '',
                       page: int = 1,
                       ) -> str:
        token = next(constants.token_generator())
        response_code = requests.get(
            'https://gist.github.com/search', headers={'Authorization': f'Token {token}'},
            timeout=1000, params={'o': 'desc', 'q': dork, 's': filter_, 'per_page': page})
        html = response_code.text
        constants.dork_search_counter += 1
        return html

    @classmethod
    def _links_exfiltr(cls, html: str, quantity: int):
        soup = BeautifulSoup(html, 'html.parser')
        links = soup.find_all('a', href=True)
        pattern = r'\"/[A-Za-z0-9-]+\/[A-Za-z0-9]+\"'
        gist_links = set()
        for link in links:
            if type(link) is dict and 'href' in link:
                href = link['href']
            else:
                href = str(link)
            if re.search(pattern, href):
                href = href.split('href=\"')[1].split('\">')[0]
                href = 'https://gist.github.com' + href
                gist_links.add(href)
        return tuple(gist_links)


    @classmethod
    def _datetim_exfiltr(cls, html: str):
        soup = BeautifulSoup(html, 'html.parser')
        elem = soup.find('relative-time')
        return elem.attrs['datetime'].split('T')[0]

    @classmethod
    def _scan(cls, url, obj):
        obj.stats.get_repo_stats()
        checker = filters.Checker(url, obj.dork, obj, 2)
        checker.clone()
        SECRETS = checker.run()
        return SECRETS

    @classmethod
    @_exc_catcher
    def run(cls, filter_: str = '', quantity: int = 15):
        checked_list = {}

        for organization in constants.dork_dict_from_DB:
            for i, dork in enumerate(constants.dork_dict_from_DB[organization]):
                if constants.dork_search_counter > constants.MAX_SEARCH_BEFORE_DUMP and len(constants.RESULT_MASS):
                    filters.dumping_data()

                constants.all_dork_search_counter += 1
                logger.info(
                    f'Current dork: {CLR["BOLD"]}{unquote(dork)}{CLR["RESET"]} {constants.all_dork_search_counter}/{constants.all_dork_counter}')
                constants.dork_search_counter += 1
                last_page_links = quantity % 10
                pull_pages = (quantity // 10) + (last_page_links > 0)

                for page in range(1, pull_pages + 1):
                    time.sleep(1)
                    html = cls._glist_request(dork, filter_, page)
                    glists_links = cls._links_exfiltr(html, quantity)
                    if len(glists_links) == 0:
                        logger.info('Not got any result.')
                        if 'rate limit' in html:
                            logger.info('Reached rate limit')
                            time.sleep(20)
                    glists_links = filters.filter_url_by_db(glists_links)
                    if len(glists_links) == 0:
                        break
                    glists_links = filters.filter_url_by_repo(glists_links)
                    if len(glists_links) == 0:
                        break

                    for _ in range(len(glists_links)):

                        time.sleep(2)
                        # Create Gist obj
                        if glists_links[_] not in checked_list.keys():
                            checked_list[glists_links[_]] = GlistObj(glists_links[_], dork, organization)
                            checked_list[glists_links[_]].secrets = cls._scan(glists_links[_], checked_list[glists_links[_]])
                            constants.RESULT_MASS['Glist_scan'][checked_list[glists_links[_]].repo_name] = checked_list[
                                glists_links[_]]
                        else:
                            constants.RESULT_MASS['Glist_scan'][checked_list[glists_links[_]].repo_name] \
                                = checked_list[glists_links[_]]
                        constants.quantity_obj_before_send += 1
                        if (constants.quantity_obj_before_send >= constants.MAX_OBJ_BEFORE_SEND or
                                constants.dork_search_counter > constants.MAX_SEARCH_BEFORE_DUMP and len(
                                    constants.RESULT_MASS)):
                            filters.dumping_data()
