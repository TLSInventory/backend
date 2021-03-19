from config import TestConfig
import pytest
from loguru import logger
from flask import url_for
from datetime import datetime
import os

import tests.conftest
from tests.ssl_server.ssl_server_fixture import httpserver_ssl_context, httpserver_ssl_add_cert
from app.utils.files import create_folder_if_doesnt_exist
cur_dir = os.path.dirname(os.path.realpath(__file__))

artifact_folder = f'{cur_dir}/artifacts'

@pytest.mark.usefixtures('client_class', 'httpserver_ssl_context', 'httpserver_ssl_add_cert')
class TestSuiteSSLyzeScan:
    def scan_website(self, domain: str, port: int = 443, httpserver = None) -> bytes:
        if domain == "localhost":
            assert httpserver.is_running()
            port = httpserver.port

        response = self.client.get(url_for("apiDebug.debug_sslyze_get_direct_scan", domain=domain, port=port))
        assert response.status_code == 200

        create_folder_if_doesnt_exist(artifact_folder)
        with open(f"{artifact_folder}/test_sslyze_scan_{int(datetime.now().timestamp())}.json", "w",
                  encoding="utf8") as f:
            f.write(response.data.decode())

        return response.data

    def test_sslyze_scan_localhost(self, httpserver):
        self.scan_website("localhost", httpserver=httpserver)

    @pytest.mark.skipif(TestConfig.local_only, reason="Scanning enabled for localhost only")
    def test_sslyze_scan_example_com(self):
        self.scan_website("example.com")

