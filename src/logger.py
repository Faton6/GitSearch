import logging
import time
from logging.handlers import TimedRotatingFileHandler

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

timestamp = time.strftime("%Y_%m_%d")
#file_handler = logging.FileHandler(f'logs/log_{timestamp}.log', 'w')
file_handler = TimedRotatingFileHandler(
        filename=f'logs/log_{timestamp}.log',
        when='midnight',        # Вращение логов происходит в полночь
        interval=1,             # Интервал вращения (1 день)
        backupCount=7,          # Хранить 7 резервных копий (7 дней)
        encoding='utf-8',       
        delay=False,            
        utc=False               
    )
file_handler.setFormatter(file_formatter)
logger.addHandler(console_handler)
logger.addHandler(file_handler)
