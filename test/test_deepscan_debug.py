#!/usr/bin/env python3
"""
Debug script to test deepscan with detailed logging
"""

import sys
import traceback
from src.logger import logger
from src import deepscan
from src import Connector

def test_specific_url():
    """Test deepscan on a specific problematic URL"""
    test_url = "https://gist.github.com/JohnPeng47/ecbcb45232afc9c034336449b299e8b8"
    
    logger.info(f"Testing deepscan on: {test_url}")
    
    try:
        # Get leak_id from database
        url_dump = Connector.dump_from_DB(mode=1)
        if test_url in url_dump:
            leak_id = url_dump[test_url][0]
            logger.info(f"Found leak_id: {leak_id}")
            
            # Get company_id
            company_id = Connector.get_company_id(int(leak_id))
            logger.info(f"Found company_id: {company_id}")
            
            # Create DeepScanManager
            manager = deepscan.DeepScanManager()
            
            # Try to scan
            logger.info("Starting _perform_gistobj_deep_scan...")
            result = manager._perform_gistobj_deep_scan(test_url, leak_id, company_id)
            
            if result:
                logger.info(f"Scan successful! Result: {result}")
            else:
                logger.error("Scan failed!")
        else:
            logger.error(f"URL {test_url} not found in database")
            
    except Exception as e:
        logger.error(f"Error during test: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(test_specific_url())
