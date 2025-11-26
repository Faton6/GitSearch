# Standart libs import
import atexit
import time
from random import choice
from concurrent.futures import ThreadPoolExecutor, Future, wait, FIRST_COMPLETED, ProcessPoolExecutor

import src.constants as const

# Project lib's import
from src.filters import Checker, CLONED, SCANNED
from src import utils
from src import Connector
from src.logger import logger, CLR
from src.searcher.parsers import (GitParserSearch, GitRepoParser, GitCodeParser, GitCommitParser)

# Track active scanners for cleanup
_active_scanners = []


def _cleanup_all_scanners():
    """Cleanup handler called at program exit to ensure data is saved."""
    for scanner in list(_active_scanners):
        try:
            scanner.cleanup()
        except Exception as e:
            logger.warning(f"Error during scanner cleanup: {e}")


# Register cleanup at module load
atexit.register(_cleanup_all_scanners)


def check_obj_pool_size():
    if (const.quantity_obj_before_send >= const.MAX_OBJ_BEFORE_SEND
        or const.dork_search_counter > const.MAX_SEARCH_BEFORE_DUMP) and len(const.RESULT_MASS):
        utils.dumping_data()
        utils.check_temp_folder_size()


class Scanner():
    parsers: tuple[GitParserSearch] = (GitCodeParser, GitRepoParser, GitCommitParser)
    scan_workers = 5
    clone_workers = 1

    def __init__(self, organization: int | None = None):
        self.checked: set = set()  # checked repos (set for O(1) lookup)
        self.org = organization
        self._cleanup_registered = False
        self._register_cleanup()
    
    def _register_cleanup(self):
        """Register cleanup handler using atexit instead of unreliable __del__."""
        if not self._cleanup_registered:
            _active_scanners.append(self)
            self._cleanup_registered = True
    
    def cleanup(self):
        """Explicit cleanup method - dumps data to DB."""
        if self in _active_scanners:
            _active_scanners.remove(self)
        Connector.dump_to_DB()
    
    def __del__(self):
        # Minimal __del__ - just remove from tracking list
        # Actual cleanup is done via atexit or explicit cleanup() call
        try:
            if self in _active_scanners:
                _active_scanners.remove(self)
        except (TypeError, AttributeError):
            pass  # Module may be partially unloaded

    def search(self):  # -> Generator[tuple[tuple[str], str]]:
        for i, dork in enumerate(const.dork_dict_from_DB[self.org]):
            # To optimize resources and decrease risk of problem with DB
            # we dump found data, clean RESULT_MASS and return to scan
            check_obj_pool_size()

            const.all_dork_search_counter += 1
            const.dork_search_counter += 1

            log_color = choice(tuple(CLR.values()))
            logger.info('Dork: %s %s %s ', log_color, dork, CLR["RESET"])

            for parser_cls in self.parsers:
                parser = parser_cls(dork, self.org)
                for obj_list in parser.get_pages():
                    check_obj_pool_size()
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
                    result = None  # Initialize result to avoid UnboundLocalError

                    for obj in temp_obj_list:
                        if obj.repo_name in self.checked or obj.repo_name in const.RESULT_MASS[scan_name]:
                            continue
                        else:
                            self.checked.add(obj.repo_name)

                        obj.stats.fetch_repository_stats()

                        checker = Checker(obj.repo_url, obj.dork, obj, 1)
                        targets[clone_exec.submit(checker.clone)] = checker


                    while True:

                        done_fs = wait(targets, return_when=FIRST_COMPLETED).done
                        if isinstance(done_fs, set):
                            if len(done_fs) == 0:
                                break
                        else:
                            done_fs = (done_fs,)

                        for fs in done_fs:
                            # if obj.repo_name in const.RESULT_MASS[scan_name]:
                            #    continue
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
                                        # Store all objects from current batch in RESULT_MASS when scan completes.
                                        # This ensures found repositories are tracked even if individual
                                        # scan results vary. The scan_name key groups results by parser type.
                                        const.RESULT_MASS[scan_name][j.repo_name] = j
                                # return

                                if isinstance(result, const.AutoVivification):
                                    checker.obj.secrets = result
                                    #self.checked[checker.obj.repo_name] = result
                            elif checker.status & CLONED > 0:
                                targets[scan_exec.submit(checker.run)] = checker
                    check_obj_pool_size()
                    if result == 1:
                        logger.info('Scan terminated early due to result=1 condition')
                        return
