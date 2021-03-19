import functools
import logging
from loguru import logger
from config import LogConfig

# If any problems with log rotation or compression appear, it might be related to the following issue:
# https://github.com/Delgan/loguru/issues/229

logger.add(LogConfig.log_folder + "{time}.log",
           backtrace=True, diagnose=True, level='DEBUG',
           compression='gz', rotation="00:00", retention="35 days")


@functools.lru_cache(maxsize=1)
def get_version_from_file() -> str:
    try:
        with open("version.txt", "r") as f:
            version_txt: str = f.read()
            return version_txt.strip()
    except FileNotFoundError as e:
        logger.warning(f'LG0003 Cannot find version file.')
    return '0.0.0'


logger.info(f'LG0001 New instance of app. Version {get_version_from_file()}')

logging.getLogger('flask_cors').level = LogConfig.cors_level

# todo: consider sending critical alert with https://github.com/liiight/notifiers to slack.
#  logoru has integration for it

# from loguru documentation

class InterceptHandler(logging.Handler):
    def emit(self, record):
        # Get corresponding Loguru level if it exists
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        # Find caller from where originated the logged message
        frame, depth = logging.currentframe(), 2
        while frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1

        logger.opt(depth=depth, exception=record.exc_info).log(level, record.getMessage())


logging.basicConfig(handlers=[InterceptHandler()], level=0)

