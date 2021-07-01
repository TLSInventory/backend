from itertools import chain
from typing import List, Type, Optional
from datetime import datetime
import sqlalchemy.orm
from flask import url_for
import pytest
from functools import reduce

import app.actions
import app.utils.files
import app.views.v2.scan_results
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
    app.utils.files.create_folder_if_doesnt_exist("tmp")

    @classmethod
    def teardown_class(cls):
        config.TestConfig.force_database_connection_string = None

    def fill_new_db(self, freezer, number_of_records=1000, filename=None):
        # filename = FULL_SCAN_LOCAL_TEST_FILENAME
        sslyze_parse_test.TestSuiteSSLyzeParse().parse_and_save_to_database_x_times(self.client, freezer, 1, filename)

        for i in range(1, number_of_records):
            x = db_models.ScanResultsHistory.query.get(1)
            db_models.db.session.expunge(x)
            sqlalchemy.orm.make_transient(x)
            x.id = None
            x.timestamp += i
            db_models.db.session.add(x)

        db_models.db.session.commit()

        try:
            register_direct(self.client)
        except AssertionError:
            logger.warning("Registration failed. Maybe some previous registration happened? Trying to continue. ")
        logger.debug("Saving to DB complete, starting retrieval.")

    @staticmethod
    def assert_json_response(res, tld_data_type: type, output_filename: Optional[str] = None):
        assert res.status_code == 200
        logger.debug(f"Number of items in res: {len(res.json)}")
        assert len(res.json)
        assert isinstance(res.json, tld_data_type)
        logger.debug("Done")

        with open(output_filename, "wb") as f:
            f.write(res.data)

    @staticmethod
    def freeze_time_from_latest_scan_in_db(freezer):
        latest_scan_result = db_models.ScanResultsHistory.query.order_by(sqlalchemy.desc(db_models.ScanResultsHistory.timestamp)).first()
        freezer.move_to(datetime.fromtimestamp(latest_scan_result.timestamp + 1))

    def setup_environment(self, freezer):
        if config.TestConfig.force_database_connection_string is None:
            self.fill_new_db(freezer, 1000)

        self.freeze_time_from_latest_scan_in_db(freezer)

        login_direct(self.client)
        access_cookie_direct(self.client)

    def test_endpoint_history(self, freezer):
        self.setup_environment(freezer)
        history = self.client.get(url_for("apiV1.api_scan_result_history_without_certs"))
        # history = app.views.v1.misc.api_scan_result_history_without_certs(1)
        self.assert_json_response(history, list, "tmp/api_history_v1.json")

    def test_endpoint_chains(self, freezer):
        self.setup_environment(freezer)
        chains = app.views.v2.scan_results.api_get_users_certificate_chains(1)
        self.assert_json_response(chains, dict, "tmp/api_chains.json")

    def test_endpoint_certificates(self, freezer):
        self.setup_environment(freezer)
        certificates = app.views.v2.scan_results.api_get_users_certificates(1)
        self.assert_json_response(certificates, dict, "tmp/api_certificates.json")

    def test_endpoint_scan_results_simplified(self, freezer):
        self.setup_environment(freezer)
        scan_results_simplified = app.views.v2.scan_results.api_get_users_scan_results_simplified(1)
        self.assert_json_response(scan_results_simplified, dict, "tmp/api_scan_results_simplified.json")

    def test_endpoint_history_v2(self, freezer):
        self.setup_environment(freezer)
        history = app.views.v2.scan_results.api_scan_result_history_without_certs(1)
        self.assert_json_response(history, dict, "tmp/api_history_v2.json")

    def test_endpoint_compatibility_history_v2(self, freezer):
        self.setup_environment(freezer)
        history = app.views.v2.scan_results.api_scan_results_history_v2(1)
        self.assert_json_response(history, list, "tmp/api_history_v2_backwards_compatible.json")
