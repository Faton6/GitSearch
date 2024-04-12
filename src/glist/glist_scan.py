# Standart libs import
import requests
from src.logger import logger, CLR
from bs4 import BeautifulSoup
import time
from urllib.parse import unquote

# Project lib's import
from src import constants
from src.glist import GlistObj
from src import filters

GIST_LINK_HTML_CLASS = 'link-overlay'


def _exc_catcher(func):
    def wrapper(*args, **kwargs):
        # res = func(*args, **kwargs)
        # return res
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
                       token,
                       filter_: str = '',
                       page: int = 1,
                       ) -> str:
        response_code = requests.get(
            f'https://gist.github.com/search?o=desc&p={page}&q={dork}&s={filter_}',
            headers={'Authorization': f'Token {token}'}, timeout=1000)
        html = response_code.text
        constants.dork_search_counter += 1
        return html

    @classmethod
    def _links_exfiltr(cls, html: str, quantity: int):
        soup = BeautifulSoup(html, 'html.parser')
        a_elements = soup.find_all('a', class_=GIST_LINK_HTML_CLASS)
        hrefs = tuple(elem['href']
                      for i, elem in enumerate(a_elements)
                      if i < quantity)
        return hrefs

    @classmethod
    def _datetim_exfiltr(cls, html: str):
        soup = BeautifulSoup(html, 'html.parser')
        elem = soup.find('relative-time')
        return elem.attrs['datetime'].split('T')[0]

    @classmethod
    def _scan(cls, url, dork):
        SECRETS = filters.CheckRepo.run(url, dork, 2)
        return SECRETS

    @classmethod
    @_exc_catcher
    def run(cls, filter_: str = '', quantity: int = 15):
        checked_list = {}
        for organization in constants.dork_dict:
            for i, dork in enumerate(constants.dork_dict[organization]):
                if constants.dork_search_counter > constants.MAX_SEARCH_BEFORE_DUMP and len(constants.RESULT_MASS):
                    filters.dumping_data()

                constants.all_dork_search_counter += 1
                logger.info(
                    f'Current dork: {CLR["BOLD"]}{unquote(dork)}{CLR["RESET"]} {constants.all_dork_search_counter}/{constants.all_dork_counter}')
                #time.sleep(1)
                token = constants.token_list[i % len(constants.token_list)]
                constants.dork_search_counter += 1
                last_page_links = quantity % 10
                pull_pages = (quantity // 10) + (last_page_links > 0)

                for page in range(1, pull_pages + 1):
                    time.sleep(1)
                    html = cls._glist_request(dork, token, filter_, page)

                    glists_links = cls._links_exfiltr(html, quantity)

                    glists_links = filters.filter_url_by_DB(glists_links)
                    if len(glists_links) == 0:
                        break
                    glists_links = filters.filter_url_by_repo(glists_links)
                    if len(glists_links) == 0:
                        break
                    for _ in range(len(glists_links)):
                        time.sleep(2)
                        # Get date of gist creation
                        get_date_gist_creation = requests.get(glists_links[_], headers={
                            'Authorization': f'Token {token}'})
                        # Create Gist obj
                        if glists_links[_] not in checked_list.keys():
                            checked_list[glists_links[_]] = GlistObj.GlistObj(glists_links[_], dork,
                                                                              cls._scan(glists_links[_], dork), organization)
                            checked_list[glists_links[_]].created_date = cls._datetim_exfiltr(get_date_gist_creation.text)
                            checked_list[glists_links[_]].updated_date = cls._datetim_exfiltr(get_date_gist_creation.text)
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
