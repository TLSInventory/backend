from flask import url_for
import pytest
import os.path
import config
from sqlalchemy import func
from datetime import datetime
from loguru import logger

import app.db_models as db_models
from tests.auth_test import login, set_debug_access_cookie

file_path = f'{config.basedir}/db/test2a.db'


def does_file_exist(path: str) -> bool:
    a = os.path.isfile(path)
    return a


# Warning: This sets existing DB as datasource. This test suite cannot be run parallel to other test suites!
if does_file_exist(file_path):
    config.TestConfig.force_database_connection_string = file_path


@pytest.mark.skipif(not does_file_exist(file_path),
                    reason="DB needed for this test is big and therefore not part of the git repository.")
@pytest.mark.usefixtures('client_class')
class TestSuiteAPIDataRetrieval:

    @login
    @set_debug_access_cookie
    def __do_authentication(self):
        pass

    def teardown_method(self, test_method):
        config.TestConfig.force_database_connection_string = None

    @staticmethod
    def url_get_history():
        return url_for("apiV1.api_scan_result_history")

    @pytest.mark.timeout(30)
    def test_get_history(self, freezer):
        # print(config.FlaskConfig.SQLALCHEMY_DATABASE_URI)
        res = db_models.db.session.query(func.max(db_models.ScanResultsHistory.timestamp))
        last_timestamp_row = res.first()
        last_timestamp = last_timestamp_row[0] if last_timestamp_row else 0

        # print(res)  # The SQL to be executed
        # print(last_timestamp)
        if last_timestamp == 0:
            logger.error("No found ScanResultsHistory in DB for TestSuiteAPIDataRetrieval? This shouldn't happen.")
            assert False

        freezer.move_to(datetime.fromtimestamp(last_timestamp+1))
        print(datetime.now())

        self.__do_authentication()

        targets = self.client.get(self.url_get_history())
        assert targets.status_code == 200

