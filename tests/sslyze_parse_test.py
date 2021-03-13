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


@pytest.mark.usefixtures('client_class')
class TestSuiteSSLyzeParse:
    def test_insert_all_scan_results(self):
        path = "tests/data/scan_results"
        if not os.path.exists(path):
            logger.warning("TEST0001 No folder from which to import scan results.")
            return

        items_in_folder = os.listdir(path)

        if len(items_in_folder) == 0:
            logger.warning("TEST0002 - No scan results to import during test.")
            return

        for filename in items_in_folder:
            # logger.warning(filename)
            result_string = read_from_file(f'{path}/{filename}')
            a = {
                "results_attached": True,
                "results": [result_string]
            }
            # sensor_collector.sslyze_save_scan_results(a)

            response = self.client.post(url_for("apiV1.api_sslyze_import_scan_results"),
                                    json=a
                                    )
            assert response.status_code == 200

