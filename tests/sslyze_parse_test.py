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
cur_dir = os.path.dirname(os.path.realpath(__file__))

path_to_scan_results = f'{cur_dir}/data/scan_results'


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

