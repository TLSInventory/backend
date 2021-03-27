import pytest
from datetime import datetime, timedelta
from app.utils.time_helper import time_source
from flask import url_for

# TimeHelper is no longer supported. Use freezer from pytest-freezegun instead.

@pytest.mark.skipif(time_source.is_mocking_forced_disabled(),
                  reason="Time mocking using time helper is forced disabled, because it's depricated.")
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


@pytest.mark.usefixtures('client_class')
class TestSuiteTimeHelperThroughAPI:
    MAX_EXPECTED_TEST_DURATION = 60*60  # seconds

    def url_current_timestamp(self):
        return url_for("apiDebug.current_timestamp")

    def test_current_timestamp_through_api(self, freezer):
        times = [
            datetime.now() - timedelta(seconds=100),
            datetime.now(),
            datetime.now() + timedelta(seconds=100)
        ]

        for time in times:
            freezer.move_to(time)
            res = self.client.get(self.url_current_timestamp())
            assert res.status_code == 200
            assert int(res.data) == int(time.timestamp())
