import sqlalchemy.orm
from flask import url_for
import pytest

import app.actions
import config
from loguru import logger

import app.db_models as db_models
from tests.auth_test import register_direct, login_direct, access_cookie_direct
import tests.sslyze_parse_test as sslyze_parse_test

# config.TestConfig.force_create_tmp_db = True  # todo: This does not get resetted, not even at the end of the test suite.
FULL_SCAN_LOCAL_TEST_FILENAME = "example.com.json"


@pytest.mark.usefixtures('client_class')
class TestSuiteAPIDataRetrieval:

    @staticmethod
    def __do_authentication(client):
        register_direct(client)
        login_direct(client)
        access_cookie_direct(client)

    @staticmethod
    def url_get_history():
        return url_for("apiV1.api_scan_result_history")

    def get_history_and_save_json_to_file(self, filename: str):
        targets = self.client.get(self.url_get_history())
        assert targets.status_code == 200

        with open(filename, "wb") as f:
            f.write(targets.data)

    def fill_new_db(self, freezer, number_of_records=1000, filename=None):
        # filename = FULL_SCAN_LOCAL_TEST_FILENAME
        sslyze_parse_test.TestSuiteSSLyzeParse().parse_and_save_to_database_x_times(self.client, freezer, 1, filename)

        self.get_history_and_save_json_to_file("tmp/test5a.json")

        for i in range(1, number_of_records):
            x = db_models.ScanResultsHistory.query.get(1)
            db_models.db.session.expunge(x)
            sqlalchemy.orm.make_transient(x)
            x.id = None
            x.timestamp += i
            db_models.db.session.add(x)

        db_models.db.session.commit()

        logger.debug("Saving to DB complete, starting retrieval.")

    def test_get_history_on_new_db(self, freezer):
        self.fill_new_db(freezer, 1000)

        self.get_history_and_save_json_to_file("tmp/test5b.json")

        # res = app.actions.get_scan_history(1, 30)
        # logger.debug(len(res))
        logger.debug("END")

