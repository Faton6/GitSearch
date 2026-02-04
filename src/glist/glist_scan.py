# Standard libs import
import time
from urllib.parse import unquote

# Project lib's import
from src.logger import logger, CLR
from src import constants
from src.LeakObj import GlistObj
from src import filters
from src import utils
from src.searcher.universal_search import UniversalGitHubSearch, SearchType


def _exc_catcher(func):
    """Decorator to catch and log exceptions."""

    def wrapper(*args, **kwargs):
        try:
            res = func(*args, **kwargs)
        except Exception as exc:
            logger.error(f"Error during glist scan in {func.__name__}(): {exc}")
        else:
            return res

    return wrapper


class GlistScan:
    """
    Optimized Gist scanner using universal search engine.

    Features:
    - Uses GitHub API instead of HTML scraping
    - Automatic rate limiting
    - GraphQL support for efficiency
    - Better error handling
    """

    @classmethod
    def _scan(cls, url, obj):
        """Scan a single gist for secrets."""
        obj.stats.fetch_repository_stats()
        checker = filters.Checker(url, obj.dork, obj, 2)
        checker.clone()
        SECRETS = checker.run()
        return SECRETS

    @classmethod
    @_exc_catcher
    def run(cls, filter_: str = "", quantity: int = 15):
        """
        Run Gist scan with universal search engine.

        Args:
            filter_: Additional filter (not used with new API)
            quantity: Maximum results per dork
        """
        checked_list = {}

        # Initialize universal search for Gists
        # Note: GitHub GraphQL API does not support Gist search, so we use REST API only
        gist_search = UniversalGitHubSearch(
            search_type=SearchType.GISTS, use_graphql=False  # GraphQL doesn't support Gist search
        )

        for organization in constants.dork_dict_from_DB:
            for i, dork in enumerate(constants.dork_dict_from_DB[organization]):
                if constants.dork_search_counter > constants.MAX_SEARCH_BEFORE_DUMP and len(constants.RESULT_MASS):
                    utils.dumping_data()
                    utils.check_temp_folder_size()

                constants.all_dork_search_counter += 1
                logger.info(
                    f'Current dork: {CLR["BOLD"]}{unquote(dork)}{CLR["RESET"]} '
                    f"{constants.all_dork_search_counter}/{constants.all_dork_counter}"
                )

                try:
                    # Use universal search instead of HTML scraping
                    collected_gists = []

                    for page_results in gist_search.search(dork, max_results=quantity):
                        collected_gists.extend(page_results)

                        # Check if we have enough results
                        if len(collected_gists) >= quantity:
                            collected_gists = collected_gists[:quantity]
                            break

                    if not collected_gists:
                        logger.info("No results found.")
                        continue

                    logger.info(f"Found {len(collected_gists)} gists")

                    # Extract URLs from results
                    glist_urls = [gist.get("html_url") for gist in collected_gists if gist.get("html_url")]

                    if not glist_urls:
                        logger.warning("No valid URLs in results")
                        continue

                    # Filter URLs
                    glist_urls = utils.filter_url_by_db(glist_urls)
                    if not glist_urls:
                        logger.debug("All URLs filtered by DB")
                        continue

                    glist_urls = utils.filter_url_by_repo(glist_urls)
                    if not glist_urls:
                        logger.debug("All URLs filtered by repo")
                        continue

                    # Process each Gist
                    for gist_url in glist_urls:
                        try:
                            # Small delay to avoid overwhelming system
                            time.sleep(1)

                            # Create or reuse Gist object
                            if gist_url not in checked_list:
                                gist_obj = GlistObj(gist_url, dork, organization)
                                checked_list[gist_url] = gist_obj

                                # Scan for secrets
                                gist_obj.secrets = cls._scan(gist_url, gist_obj)

                                # Store results
                                constants.RESULT_MASS["Glist_scan"][gist_obj.repo_name] = gist_obj
                            else:
                                # Reuse existing object
                                constants.RESULT_MASS["Glist_scan"][checked_list[gist_url].repo_name] = checked_list[
                                    gist_url
                                ]

                            constants.quantity_obj_before_send += 1

                            # Dump data if needed
                            if (
                                constants.quantity_obj_before_send >= constants.MAX_OBJ_BEFORE_SEND
                                or constants.dork_search_counter > constants.MAX_SEARCH_BEFORE_DUMP
                                and len(constants.RESULT_MASS)
                            ):
                                utils.dumping_data()
                                utils.check_temp_folder_size()

                        except Exception as e:
                            logger.error(f"Error processing gist {gist_url}: {e}")
                            continue

                except Exception as e:
                    logger.error(f'Error searching for dork "{dork}": {e}')
                    continue
