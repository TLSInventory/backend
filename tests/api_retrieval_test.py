from datetime import datetime
import sqlalchemy.orm
from flask import url_for
import pytest
from functools import reduce

import app.actions
import config
from loguru import logger

import app.db_models as db_models
import app.db_schemas as db_schemas
from tests.auth_test import register_direct, login_direct, access_cookie_direct
import tests.sslyze_parse_test as sslyze_parse_test
import app.utils.db.basic as db_utils

# config.TestConfig.force_database_connection_string = "../db/test2a.db"
# config.TestConfig.force_create_tmp_db = True  # todo: This does not get resetted, not even at the end of the test suite.
FULL_SCAN_LOCAL_TEST_FILENAME = "example.com.json"


@pytest.mark.usefixtures('client_class')
class TestSuiteAPIDataRetrieval:

    @classmethod
    def teardown_class(cls):
        config.TestConfig.force_database_connection_string = None

    @staticmethod
    def __do_authentication(client):
        register_direct(client)
        login_direct(client)
        access_cookie_direct(client)

    @staticmethod
    def url_get_history():
        # return url_for("apiV1.api_scan_result_history_with_certs")
        return url_for("apiV1.api_scan_result_history_without_certs")

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

    @staticmethod
    def freeze_time_from_latest_scan_in_db(freezer):
        latest_scan_result = db_models.ScanResultsHistory.query.order_by(sqlalchemy.desc(db_models.ScanResultsHistory.timestamp)).first()
        freezer.move_to(datetime.fromtimestamp(latest_scan_result.timestamp + 1))

    def test_get_history(self, freezer):
        if config.TestConfig.force_database_connection_string is None:
            self.fill_new_db(freezer, 1000)

        self.freeze_time_from_latest_scan_in_db(freezer)

        login_direct(self.client)
        access_cookie_direct(self.client)

        self.get_history_and_save_json_to_file("tmp/test5b.json")
        logger.debug("END")

    @pytest.mark.skip(reason="Work in progress")
    def test_direct_access_to_certificate_chains(self):
        res = app.actions.get_scan_history(1, 1)
        # b = db_schemas.TargetSchema().dump(list(map(lambda x: x.Target, res)), many=True)

        # res = res[:10]
        # logger.debug(res)

        ans1a = map(lambda x: x.ScanResultsSimplified, res)
        ans1b = map(lambda x: x.verified_certificate_chains_lists_ids if x else None, ans1a)
        ans2 = map(lambda x: db_utils.split_array_to_tuple(x) if x else None, ans1b)
        ans2b = list(ans2)

        ans3 = filter(lambda x: x, ans2b)
        ans4 = reduce(lambda x, y: x + y, ans3, ())
        ans4b = set(ans4)

        logger.debug(ans4b)

        res = db_models.db.session.query(db_models.CertificateChain) \
            .filter(db_models.CertificateChain.id.in_(list(ans4b))) \
            .all()

        # logger.debug(res)
        logger.debug("SQL Complete")

        c = db_schemas.CertificateChainSchema().dumps(res, many=True)
        with open("tmp/test5c.json", "w") as f:
            f.write(c)
