# Standart libs import
# import signal
import time

# from urllib.parse import unquote
from concurrent.futures import ThreadPoolExecutor, Future, wait,FIRST_COMPLETED

import src.constants as c

# Project lib's import
from src.filters import Connector, dumping_data, Checker, CLONED, SCANNED
from src.logger import logger
# from typing import Generator

from src.searcher.parsers import (GitParser, GitRepoParser, GitCodeParser,
                                  GitCommitParser)

class Scanner():
    parsers: tuple[GitParser] = (GitCodeParser, GitRepoParser, GitCommitParser)
    scan_workers = 5
    clone_workers = 1

    def __init__(self, organization: str | None = None):
        self.checked: dict = {} # checked repos
        self.org = organization

    def __del__(self):
        Connector.dump_to_DB()

    def search(self): #-> Generator[tuple[tuple[str], str]]:
        for dorks in c.dork_dict.values():
            for i, dork in enumerate(dorks):
                token = c.token_list[i % len(c.token_list)]
                # To optimize resources and decrease risk of problem with DB
                # we dump found data, clean RESULT_MASS and return to scan

                if (c.quantity_obj_before_send
                    >= c.MAX_OBJ_BEFORE_SEND
                    or (c.dork_search_counter
                        > c.MAX_SEARCH_BEFORE_DUMP
                        and len(c.RESULT_MASS))):
                    dumping_data()

                c.all_dork_search_counter += 1
                c.dork_search_counter += 1
                # TODO it change to generator it

                logger.info('Dork: %s', dork)

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
                    logger.info('Got empty page, iterating further...')
                    continue

                t: dict[Future, Checker] = {}

                for obj in obj_list:
                    if obj.repo_name not in self.checked:
                        self.checked.update({f'{obj.repo_name}': ''})
                    else:
                        obj.secrets = self.checked[obj.repo_name]

                    checker = Checker(obj.repo_url, obj.dork, obj)
                    t[clone_exec.submit(checker.clone)] = checker

                while True:
                    done_fs = wait(t, return_when=FIRST_COMPLETED).done
                    if isinstance(done_fs, set):
                        if len(done_fs) == 0:
                            break
                    else:
                        done_fs = (done_fs, )

                    for fs in done_fs:
                        checker = t[fs]
                        try:
                            result = fs.result()
                        except Exception as exc:
                            logger.error("Failed to scan %s: %s", checker.url,
                                         exc)
                            continue
                        del t[fs]

                        if checker.status == CLONED:
                            t[scan_exec.submit(checker.run)] = checker
                        elif checker.status == SCANNED:
                            if result == 1:
                                for j in obj_list:
                                    # HACK what is this
                                    c.RESULT_MASS[scan_name][j.repo_name] = j
                                    return

                            if isinstance(result, c.AutoVivification):
                                checker.obj.secrets = result
                                self.checked[checker.obj.repo_name] = result

                if c.quantity_obj_before_send >= c.MAX_OBJ_BEFORE_SEND:
                    dumping_data()
