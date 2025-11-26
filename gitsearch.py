# Standard library imports
import sys
import os
import subprocess
import signal
import atexit

# Project library imports
from src import constants
from src import Connector
from src.logger import logger
from src.searcher.scanner import Scanner
from src.glist.glist_scan import GlistScan
from src import deepscan
from src import utils
from src.api_client import GitSearchAPIClient


def cleanup_on_exit():
    """Cleanup handler called at program exit."""
    try:
        # Shutdown AI worker pool gracefully
        try:
            from src.ai_worker import shutdown_ai_worker_pool
            shutdown_ai_worker_pool(wait=True)
            logger.info('AI worker pool shutdown complete')
        except ImportError:
            pass
        except Exception as e:
            logger.warning(f'Error shutting down AI worker pool: {e}')
        
        # Close database connection
        Connector.APIClient.close()
        logger.info('Database connection closed')
    except Exception as e:
        logger.warning(f'Error during cleanup: {e}')


def signal_shutdown(signum=None, frame=None):
    """
    Handle shutdown signal gracefully.
    
    Args:
        signum: Signal number (optional)
        frame: Current stack frame (optional)
    """
    logger.info('Stopping gracefully. Press Ctrl+C again to force quit')
    Connector.dump_to_DB()
    cleanup_on_exit()
    sys.exit(0)


# Register cleanup at module load
atexit.register(cleanup_on_exit)


if __name__ == "__main__":
    subprocess.run(['git', 'config', '--global', '--add', 'safe.directory', '/app'])
    
    # Initialize GitHub Rate Limiter
    try:
        constants._init_rate_limiter()
        logger.info('GitHub Rate Limiter initialized')
    except Exception as e:
        logger.warning(f'Failed to initialize Rate Limiter: {e}')
    
    # DEBUG TESTS:
    if constants.RUN_TESTS:
        logger.info('Running tests...')
        # Install pytest if not already installed
        if not subprocess.run(['pip', 'show', 'pytest'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            logger.info('Installing pytest...')
        subprocess.run(['pip', 'install', 'pytest'])
        logger.info('Running pytest...')
        subprocess.run([sys.executable, '-m', 'pytest', '-q'])
    
    if constants.CONFIG_FILE['create_report'] == 'yes':        
        logger.info('Creating report from config')
        from src.report_generator import generate_report_from_config
        generate_report_from_config()
        logger.info('Report created')
        sys.exit(0)   
    
    if not constants.token_tuple or constants.token_tuple[0] == '-':
        logger.warning('Warning: Token not set. Open config.json and put token to token_list')
    
    if constants.url_DB != '-':
        constants.url_from_DB = Connector.dump_from_DB()
        utils.exclude_list_update()
        constants.dork_dict_from_DB = Connector.dump_target_from_DB()
    else:
        constants.url_from_DB = '-'
        constants.dork_dict_from_DB = constants.CONFIG_FILE['target_list']


    
    constants.all_dork_counter = 0  # quantity of all dorks
    with open(f'{constants.MAIN_FOLDER_PATH}/src/dorks.txt', 'r') as dorks_file:
        constants.dork_list_from_file = [line.rstrip() for line in dorks_file]
    
    # Optimization: Use set for O(1) lookup instead of O(n) list membership test
    for company in constants.dork_dict_from_DB:
        initial_company_dorks = list(constants.dork_dict_from_DB[company])[3:]  # Create a copy to iterate over
        existing_dorks = set(constants.dork_dict_from_DB[company])  # Convert to set for fast lookup
        
        for initial_dork in initial_company_dorks:
            constants.all_dork_counter += 1
            for base_dork in constants.dork_list_from_file:
                combined_dork = f"{initial_dork} {base_dork}"
                if combined_dork not in existing_dorks:  # O(1) set lookup instead of O(n) list lookup
                    constants.dork_dict_from_DB[company].append(combined_dork)
                    existing_dorks.add(combined_dork)  # Update set
                    constants.all_dork_counter += 1
                    constants.leak_check_list.append(base_dork)  # Assuming base_dorks are also leak_check_list items

   
    constants.all_dork_counter *= 2

    signal.signal(signal.SIGINT, signal_shutdown)


    old_dir = os.getcwd()
    os.chdir(constants.SEARCH_FOLDER_PATH)
    logger.info(f'Current directory: {constants.SEARCH_FOLDER_PATH}')

    try:
        # List scan
        logger.info('Start List scan')
        deepscan.list_search()

        # Github Gist scan
        logger.info('Start Gist scan')
        #GlistScan.run(filter_='updated', quantity=30)
        utils.dumping_data()

        # Github scan
        logger.info('Start Github scan')
        for org in constants.dork_dict_from_DB:
            Scanner(org).gitscan()
        utils.dumping_data()


        logger.info('Start Deepscan scan')
        constants.RESULT_MASS = constants.AutoVivification()
        deep_scan_manager = deepscan.DeepScanManager()
        deep_scan_manager.run()
        
        # Print GitHub API usage statistics
        try:
            from src.github_rate_limiter import get_rate_limiter, is_initialized
            if is_initialized():
                logger.info('=' * 80)
                logger.info('GitHub API Usage Summary')
                logger.info('=' * 80)
                rate_limiter = get_rate_limiter()
                rate_limiter.print_status()
        except Exception as e:
            logger.debug(f'Could not print rate limiter status: {e}')


        logger.info('Start Re scan')
        constants.RESULT_MASS = constants.AutoVivification()
        deep_scan_manager = deepscan.DeepScanManager()
        deep_scan_manager.run(mode=1)  # mode=1 for re-scan

        Connector.update_result_filed_in_DB()
        
    except KeyboardInterrupt:
        logger.info('Received interrupt signal, saving data...')
        Connector.dump_to_DB()
    except Exception as e:
        logger.error(f'Critical error during scanning: {e}')
        Connector.dump_to_DB()
        raise
    finally:
        # Cleanup temp files
        if os.path.exists(f'{constants.MAIN_FOLDER_PATH}/temp/temp_exclude_list.txt'):
            os.remove(f'{constants.MAIN_FOLDER_PATH}/temp/temp_exclude_list.txt')

        os.chdir(old_dir)
        logger.info(f'Back to directory: {old_dir}')