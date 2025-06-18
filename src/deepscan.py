import os

from src.logger import logger
from src import Connector
from src import constants
from src.LeakObj import RepoObj
from src import filters
from src.searcher.scanner import Scanner

checked_list = {}

# TODO need fix
def deep_scan():
    url_to_deepscan = constants.AutoVivification()
    mode_for_dump_from_DB = 1  # type of returned dump_from_DB data
    url_dump = constants.dork_dict_from_DB  # list with dict: {url:final_resul}
    for url_from_DB in url_dump.keys():
        if type(url_dump[url_from_DB][0]) is str and int(url_dump[url_from_DB][0]) == constants.RESULT_CODE_TO_DEEPSCAN:
            url_to_deepscan[url_from_DB] = [url_dump[url_from_DB][1], None]

    for url in url_to_deepscan.keys():
        mode_for_scan = 3
        url_to_deepscan[url][1], url_to_deepscan[url][2] = filters.Checker.run(url, 'None', mode_for_scan, constants.AI_CONFIG)
    mode_for_dump_to_DB = 1

    for url in list(url_to_deepscan.keys()):
        raw_report = Connector.dump_row_data_from_DB(url_to_deepscan[url][0])
        temp_data = url_to_deepscan[url][1]
        if (len(raw_report['grepscan']) == len(temp_data['grepscan'])
                and len(raw_report['whispers']) == len(temp_data['whispers'])
                and len(raw_report['trufflehog']) == len(temp_data['trufflehog'])
                and len(raw_report['deepsecrets']) == len(temp_data['deepsecrets'])):
            del url_to_deepscan[url]
            continue
    # ioc_finder
    Connector.dump_to_DB(mode_for_dump_to_DB, url_to_deepscan)


f'''
Add List scan - scanning github by input urls.
For this you need create file
And get file name as arg:
python gitsearch /path/to/file 
OR you can input github url to /temp/list_to_scan.txt
'''


def list_search(input_file_path: str = None):  # TODO: add gist.github
    """
    Scans GitHub repositories from a list of URLs provided in a file.
    If input_file_path is not provided, it defaults to constants.MAIN_FOLDER_PATH/temp/list_to_scan.txt.
    """
    target_file = input_file_path if input_file_path else str(constants.MAIN_FOLDER_PATH / "temp" / "list_to_scan.txt")

    if not os.path.exists(target_file):
        logger.info(f"List scan file not found: {target_file}")
        return

    with open(target_file, 'r') as list_file:
        url_list = [line.rstrip() for line in list_file if line.strip() and not line.strip().startswith('//')]

    if not url_list:
        logger.info("No valid URLs found in the list scan file.")
        return

    _list_scan(url_list)

    # Mark processed URLs by prefixing with '//'
    with open(target_file, 'w') as list_file:
        for url in url_list:
            list_file.write(f"//{url}\n")


def _list_scan(url_list):
    logger.info(f"Starting list scan for {len(url_list)} URLs.")
    
    # use a specific one if applicable
    if url_list[0] not in constants.dork_dict:
        constants.dork_dict[url_list[0]] = []

    # Convert URLs to RepoObj and add to a temporary dork_dict entry for Scanner
    repo_objs = []
    for url in url_list:
        # Extract owner/repo from URL for RepoObj. This might need more robust parsing.
        try:
            parts = url.split('/')
            owner_repo = f"{parts[3]}/{parts[4]}" # Assuming github.com/owner/repo format
            repo_objs.append(RepoObj(url, {'full_name': owner_repo, 'owner': {'login': parts[3]}}, 'list_scan_dork'))
        except IndexError:
            logger.warning(f"Could not parse URL for RepoObj: {url}")
            continue

    # Temporarily add these RepoObjs to dork_dict for the Scanner to process
    # This is a simplification; a more robust solution might involve a dedicated Scanner method
    # that accepts a list of RepoObjs directly.
    constants.dork_dict[url_list[0]].extend([obj.repo_url for obj in repo_objs])

    # Use the existing Scanner to process the repositories
    scanner = Scanner(url_list[0])
    scanner.gitscan() # This will now process the URLs added to dork_dict

    filters.dumping_data()
