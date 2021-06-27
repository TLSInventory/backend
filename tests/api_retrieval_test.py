from itertools import chain
from typing import List, Type
from datetime import datetime
import sqlalchemy.orm
from flask import url_for
import pytest
from functools import reduce

import app.actions
import app.utils.files
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

        try:
            register_direct(self.client)
        except AssertionError:
            logger.warning("Registration failed. Maybe some previous registration happened? Trying to continue. ")
        logger.debug("Saving to DB complete, starting retrieval.")

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


    @pytest.mark.skip(reason="This test is disabled until we stabilize the v2 API.")
    def test_get_history(self, freezer):
        self.setup_environment(freezer)

        self.get_history_and_save_json_to_file("tmp/test5b.json")
        logger.debug("END")

    def test_direct_access_to_certificate_chains(self, freezer):
        self.setup_environment(freezer)

        logger.debug("Start getting chains")
        res_chains = app.actions.get_certificate_chains(1)

        logger.debug("Start serializing chains")
        c = db_schemas.CertificateChainSchemaWithoutCertificates().dumps(res_chains, many=True)
        with open("tmp/test5c.json", "w") as f:
            f.write(c)

        logger.debug("Start getting certificates")
        res_certs = app.actions.get_certificates(res_chains)

        logger.debug("Start serializing certificates")
        d = db_schemas.CertificateSchema().dumps(res_certs, many=True)
        with open("tmp/test5d.json", "w") as f:
            f.write(d)

        logger.debug("Done")

    def test_slow_endpoints(self, freezer):
        self.setup_environment(freezer)

        chains = self.client.get(url_for("apiV1.api_get_users_certificate_chains"))
        assert chains.status_code == 200
        logger.debug(f"Chains len: {len(chains.json)}")
        assert len(chains.json)

        certificates = self.client.get(url_for("apiV1.api_get_users_certificates"))
        assert certificates.status_code == 200
        logger.debug(f"Certificates len: {len(certificates.json)}")
        assert len(chains.json)

        logger.debug("Done")

