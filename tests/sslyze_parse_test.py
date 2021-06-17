import config

# Setting env variables using mock env is too late, config already has it's ENVs loaded. This is a hack, but works.
config.SensorCollector.SEND_RESULTS_TO_LOCAL_DB = True

import os
import json
import pytest
from loguru import logger
from flask import url_for

from app.utils.files import read_from_file
import tests.conftest
from tests.auth_test import login, register, set_debug_access_cookie
from tests.scan_scheduler_test import target_add_data
import app.db_models as db_models

cur_dir = os.path.dirname(os.path.realpath(__file__))

path_to_scan_results = f'{cur_dir}/data/scan_results'

target_from_local_test_data_file = {
    "hostname": "localhost",
    # "ip_address": "127.0.0.1",
    "port": 35051
}


@pytest.mark.usefixtures('client_class')
class TestSuiteSSLyzeParse:

    @pytest.mark.parametrize("filename", os.listdir(path_to_scan_results),)
    def test_parse_single_sslyze_scan_from_file(self, filename):
        result_string = read_from_file(f'{path_to_scan_results}/{filename}')
        a = {
            "results_attached": True,
            "results": [json.loads(result_string)]
        }

        response = self.client.post(url_for("apiV1.api_sslyze_import_scan_results"),
                                json=a
                                )
        assert response.status_code == 200

    @register
    @login
    def test_parse_two_related_scans(self):
        assert self.client.get(url_for("apiDebug.debugSetAccessCookie")).status_code == 200
    @set_debug_access_cookie

        filename = "local_scan.json"
        result_string = read_from_file(f'{path_to_scan_results}/{filename}')
        a = {
            "results_attached": True,
            "results": [json.loads(result_string)]
        }

        response = self.client.put(
            url_for("apiV1.api_target"),
            json=target_add_data(
                hostname=target_from_local_test_data_file["hostname"],
                # ip=target_from_local_test_data_file["ip_address"],
                port=target_from_local_test_data_file["port"]
              )
        )
        assert response.status_code == 200

        response = self.client.post(url_for("apiV1.api_sslyze_import_scan_results"), json=a)
        assert response.status_code == 200

        response = self.client.post(url_for("apiV1.api_sslyze_import_scan_results"), json=a)
        assert response.status_code == 200

        res = db_models.db.session.query(db_models.ScanResultsHistory).all()
        assert len(res) == 2

