import logging
import time

'''
    Logging config.json file
'''

CLR = {
    "GREEN": '\033[32m',
    "YELLOW": '\033[33m',
    "RED": '\033[31m',
    "VERYRED": '\033[91m',
    "bold_red": "\x1b[31;1m",
    "blue": "\x1b[1;34m",
    "light_blue": "\x1b[1;36m",
    "RESET": '\033[0m',
    "purple": "\x1b[1;35m",
    "BOLD": '\033[1m'
}

logger = logging.getLogger('my_logger')
logger.setLevel(logging.DEBUG)

console_formatter = logging.Formatter('%(message)s')
file_formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s in %(filename)s, %(lineno)d line')

console_handler = logging.StreamHandler()
console_handler.setFormatter(console_formatter)

timestamp = time.strftime("%Y%m%d-%H%M")
file_handler = logging.FileHandler(f'logs/log_{timestamp}.log', 'w')
file_handler.setFormatter(file_formatter)

logger.addHandler(console_handler)
logger.addHandler(file_handler)
