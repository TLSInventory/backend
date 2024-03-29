import config

# Setting env variables using mock env is too late, config already has it's ENVs loaded. This is a hack, but works.
config.SensorCollector.SEND_RESULTS_TO_LOCAL_DB = True

import os
import json
import pytest
from loguru import logger
from flask import url_for
from datetime import timedelta, datetime

from app.utils.files import read_from_file
import tests.conftest
from tests.auth_test import login_direct, register_direct, access_cookie_direct
from tests.scan_scheduler_test import target_add_data
import app.db_models as db_models

CUR_DIR = os.path.dirname(os.path.realpath(__file__))

PATH_TO_SCAN_RESULTS = f'{CUR_DIR}/data/scan_results'

LOCAL_TEST_DATA_FILENAME = 'local_scan.json'
TARGET_FROM_LOCAL_TEST_DATA_FILE = {
    "hostname": "localhost",
    # "ip_address": "127.0.0.1",
    "port": 35051
}


@pytest.mark.usefixtures('client_class')
class TestSuiteSSLyzeParse:

    @pytest.mark.parametrize("filename", os.listdir(PATH_TO_SCAN_RESULTS), )
    def test_parse_single_sslyze_scan_from_file(self, freezer, filename):
        # This test doesn't save some things to DB. It's testing the parsing itself, not whether the result is correctly persisted.
        data = self.load_result_file_to_dict(filename)
        self.parse_scan_multiple_times(self.client, freezer, data=data, insert_n_times=1)

    def test_parsing_and_saving_to_db(self, freezer):
        self.parse_and_save_to_database_x_times(self.client, freezer, 1)

    def test_parsing_and_saving_multiple_results_of_same_target(self, freezer):
        self.parse_and_save_to_database_x_times(self.client, freezer, 2)

    # --- HELPER METHODS ---

    @staticmethod
    def parse_and_save_to_database_x_times(client, freezer, save_x_times: int = 1, filename=None):
        if filename is None:
            filename = LOCAL_TEST_DATA_FILENAME
        data = TestSuiteSSLyzeParse.load_result_file_to_dict(filename)

        register_direct(client)
        login_direct(client)
        access_cookie_direct(client)

        TestSuiteSSLyzeParse.add_target_from_scan_file(client,
                                                       hostname=data["results"][0]["target"]["target_definition"]["hostname"],
                                                       port=data["results"][0]["target"]["target_definition"]["port"])
        TestSuiteSSLyzeParse.parse_scan_multiple_times(client, freezer, data=data, insert_n_times=save_x_times)

        res = db_models.db.session.query(db_models.ScanResultsHistory).all()
        assert len(res) == save_x_times

    @staticmethod
    def load_result_file_to_dict(filename: str) -> dict:
        result_string = read_from_file(f'{PATH_TO_SCAN_RESULTS}/{filename}')
        a = {
            "results_attached": True,
            "results": [json.loads(result_string)]
        }
        return a

    @staticmethod
    def add_target_from_scan_file(client, hostname=None, port=None):
        if hostname is None:
            hostname = TARGET_FROM_LOCAL_TEST_DATA_FILE["hostname"]
        if port is None:
            port = TARGET_FROM_LOCAL_TEST_DATA_FILE["port"]

        response = client.put(
            url_for("apiV1.api_target"),
            json=target_add_data(
                hostname=hostname,
                # ip=target_from_local_test_data_file["ip_address"],
                port=port,
              )
        )
        assert response.status_code == 200

    @staticmethod
    def parse_scan_multiple_times(client, freezer, data: dict, insert_n_times: int = 1):
        dt = datetime.now()
        for i in range(insert_n_times):
            freezer.move_to(dt)
            response = client.post(url_for("apiV1.api_sslyze_import_scan_results"), json=data)
            assert response.status_code == 200
            dt += timedelta(seconds=1)


