# Standart libs import
# import signal
import time

# from urllib.parse import unquote
from concurrent.futures import ThreadPoolExecutor, Future, wait, FIRST_COMPLETED, ProcessPoolExecutor

import src.constants as const

# Project lib's import
from src.filters import Connector, dumping_data, Checker, CLONED, SCANNED
from src.logger import logger
# from typing import Generator

from src.searcher.parsers import (GitParserSearch, GitRepoParser, GitCodeParser, GitCommitParser)


def check_obj_pool_size():
    if (const.quantity_obj_before_send >= const.MAX_OBJ_BEFORE_SEND
        or const.dork_search_counter > const.MAX_SEARCH_BEFORE_DUMP) and len(const.RESULT_MASS):
        dumping_data()


class Scanner():
    parsers: tuple[GitParserSearch] = (GitCodeParser, GitRepoParser, GitCommitParser)
    scan_workers = 5
    clone_workers = 1

    def __init__(self, organization: int | None = None):
        self.checked: dict = {}  # checked repos
        self.org = organization

    def __del__(self):
        Connector.dump_to_DB()

    def search(self):  # -> Generator[tuple[tuple[str], str]]:
        for i, dork in enumerate(const.dork_dict[self.org]):
            token = const.token_list[i % len(const.token_list)]
            # To optimize resources and decrease risk of problem with DB
            # we dump found data, clean RESULT_MASS and return to scan

            check_obj_pool_size()

            const.all_dork_search_counter += 1
            const.dork_search_counter += 1
            logger.info(f'Dork: {dork}')

            for parser_cls in self.parsers:
                parser = parser_cls(dork, self.org, token)
                for obj_list in parser.get_pages():
                    yield obj_list, str(parser)

    def gitscan(self):
        logger.info('Scan started at %s', time.strftime('%Y-%m-%d-%H-%M'))

        with ThreadPoolExecutor(max_workers=self.scan_workers) as scan_exec, \
                ThreadPoolExecutor(max_workers=self.clone_workers) as clone_exec:

            for obj_list, scan_name in self.search():

                if len(obj_list) < 1:
                    logger.info('Got empty page from, iterating further...')
                    time.sleep(5)
                    continue

                for splitter in range(int(len(obj_list) / const.MAX_OBJ_BEFORE_SEND)):
                    check_obj_pool_size()
                    if splitter * const.MAX_OBJ_BEFORE_SEND < len(obj_list):
                        temp_obj_list = obj_list[
                                        splitter * const.MAX_OBJ_BEFORE_SEND:(splitter + 1) * const.MAX_OBJ_BEFORE_SEND]
                    else:
                        continue
                        # logger.info('End %s search', scan_name)

                    targets: dict[Future, Checker] = {}
                    token_counter: int = 0
                    for obj in temp_obj_list:
                        if (obj.repo_name in self.checked and len(self.checked[obj.repo_name])) or obj.repo_name in \
                                const.RESULT_MASS[scan_name]:
                            continue

                        token_counter += 1
                        checker = Checker(obj.repo_url, obj.dork, obj, 1, const.token_list[token_counter % len(const.token_list)])
                        targets[clone_exec.submit(checker.clone)] = checker

                    while True:

                        done_fs = wait(targets, return_when=FIRST_COMPLETED).done
                        if isinstance(done_fs, set):
                            if len(done_fs) == 0:
                                break
                        else:
                            done_fs = (done_fs,)

                        for fs in done_fs:
                            #if obj.repo_name in const.RESULT_MASS[scan_name]:
                            #    continue
                            check_obj_pool_size()
                            checker = targets[fs]
                            try:
                                result = fs.result()
                            except Exception as exc:
                                logger.error("Failed to scan %s: %s", checker.url,
                                             exc)
                                continue
                            finally:
                                del targets[fs]

                            if checker.status & SCANNED > 0:
                                # if result == 1:
                                for j in obj_list:
                                    if j.repo_name not in const.RESULT_MASS[scan_name]:
                                        # HACK what is this
                                        const.RESULT_MASS[scan_name][j.repo_name] = j
                                # return

                                if isinstance(result, const.AutoVivification):
                                    checker.obj.secrets = result
                                    self.checked[checker.obj.repo_name] = result
                            elif checker.status & CLONED > 0:
                                targets[scan_exec.submit(checker.run)] = checker

                    if result == 1:
                        logger.info('8'*80)
                        return
