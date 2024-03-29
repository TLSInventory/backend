from typing import Optional
from loguru import logger
from datetime import datetime, timedelta


def datetime_to_timestamp(x: datetime) -> Optional[int]:
    if x is None:
        return None
    return int(x.timestamp())


def timestamp_to_datetime(x: int) -> datetime:
    return datetime.utcfromtimestamp(x)


class TimeHelper:
    """
    DEPRECATED: This module was used for tests, but we've switched to pytest-freezegun.
    All references to this module will be later removed, for now the mocking functionality is disabled.

    ---

    Instance of this class should serve as a single source of truth for time in the whole application.
    It allows dynamic mocking of time, which is especially useful in tests of scheduler functions.
    """

    def __init__(self):
        self.__mock: bool = False
        self.__mocked_time: datetime = datetime.fromtimestamp(0)
        self.__force_disable_mocking: bool = True

    def mock(self, status: Optional[bool] = None) -> bool:
        if status is not None and self.__mock != status:
            # todo: consider adding logger.warning for situation when time mocking is enabled in production
            if self.is_mocking_forced_disabled():
                logger.error("Time mocking is forced disabled. Call to enable it was canceled.")
                return self.__mock
            self.__mock = status
            logger.debug(f"Time mocking {'enabled' if status else 'disabled'}")

        return self.__mock

    def set_now(self):
        self.set_time(datetime.now())

    def set_time(self, mock_time: datetime):
        self.__mocked_time = mock_time

    def offset_time(self, td: timedelta):
        self.__mocked_time += td

    def time(self) -> datetime:
        if self.mock():
            return self.__mocked_time
        return datetime.now()

    def timestamp(self) -> int:
        return datetime_to_timestamp(self.time())

    def is_mocking_forced_disabled(self):
        return self.__force_disable_mocking


time_source = TimeHelper()

