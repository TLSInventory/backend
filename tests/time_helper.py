import pytest
from datetime import datetime, timedelta
from app.utils.time_helper import time_source

class TestSuiteTimeHelper:
    ALLOWED_TIME_DIFF = timedelta(seconds=1)

    def test_current_time(self):
        test_time = time_source.time()
        assert abs(datetime.now() - test_time) < self.ALLOWED_TIME_DIFF
        assert abs(datetime.fromtimestamp(0) - test_time) > self.ALLOWED_TIME_DIFF

    def test_mocked_time(self):
        mock_time = datetime.fromtimestamp(42)
        time_source.set_time(mock_time)

        assert time_source.mock() == False
        assert abs(datetime.now() - time_source.time()) < self.ALLOWED_TIME_DIFF

        assert time_source.mock(True)
        assert mock_time == time_source.time()

        assert time_source.mock(False) == False
        assert abs(datetime.now() - time_source.time()) < self.ALLOWED_TIME_DIFF

    def test_set_now(self):
        time_source.mock(True)
        time_source.set_now()
        assert abs(datetime.now() - time_source.time()) < self.ALLOWED_TIME_DIFF

    def test_offset(self):
        time_source.mock(True)
        mock_time = datetime.fromtimestamp(42)
        time_source.set_time(mock_time)

        td = timedelta(seconds=28)

        assert abs(mock_time - time_source.time()) < self.ALLOWED_TIME_DIFF

        time_source.offset_time(td)
        assert abs(mock_time + td - time_source.time()) < self.ALLOWED_TIME_DIFF

        time_source.offset_time(-td)
        assert abs(mock_time - time_source.time()) < self.ALLOWED_TIME_DIFF

    def test_timestamp(self):
        time_source.mock(True)
        for i in range(5):
            mock_time = datetime.fromtimestamp(i)
            time_source.set_time(mock_time)
            assert time_source.timestamp() == i
