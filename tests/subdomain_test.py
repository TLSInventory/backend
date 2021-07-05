from typing import Optional

import pytest
from flask import url_for

from config import TestConfig
from tests.auth_test import AuthTestSuiteConfig

from app.views.v1.subdomain_util import *


def pytest_configure():
    pytest.first_batch = 0


@pytest.mark.skipif(TestConfig.local_only, reason="Adding subdomains would require connections to crt.sh")
@pytest.mark.usefixtures('client_class')
class TestSubdomainSuite:

    def do_authentication(self, registration_data: dict):
        assert self.client.post(url_for("apiV1.api_register"), json=registration_data).status_code == 200
        assert self.client.post(url_for("apiV1.api_login"), json=AuthTestSuiteConfig.login_data_from_register(registration_data)).status_code == 200
        assert self.client.get(url_for("apiDebug.debugSetAccessCookie")).status_code == 200

    def target_add_data(self, hostname:str = "example.com", ip: Optional[str]=None):
        return {
            "target": {"id": None, "hostname": hostname, "port": None, "ip_address": ip, "protocol": "HTTPS"},
            "scanOrder": {"periodicity": 43200, "active": None}
        }

    def add_target(self, json_data):
        # adding a target without IP will result
        # in DNS query on every enque for scan
        res = self.client.put(url_for("apiV1.api_target"), json=json_data)
        assert res.status_code == 200
        return res

    def test_add_subdomains(self):
        self.do_authentication(AuthTestSuiteConfig.register_data1)
        self.add_target(self.target_add_data())
        self.add_target(self.target_add_data(hostname="borysek.net"))  # for further testing, so I know the ID
        _, fb, res = api_add_subdomains(1)
        assert res == 200
        pytest.first_batch = fb

    def test_same_subdomain_different_user(self):
        self.test_add_subdomains()  # Each test runs isolated, unless explicitly invoked. I.e. testing different username on it's own doesn't make much sense, unless you also re-register the first user.
        self.do_authentication(AuthTestSuiteConfig.register_data2)
        self.add_target(self.target_add_data())
        _, fb, res = api_add_subdomains(1)
        assert res == 200
        assert fb == pytest.first_batch

    def test_repeatedly_add_subdomains(self):
        self.do_authentication(AuthTestSuiteConfig.register_data1)
        self.add_target(self.target_add_data())
        _, _, res = api_add_subdomains(1)
        assert res == 200
        _, added, res = api_add_subdomains(1)
        assert res == 200
        assert added == 0

    def test_add_untracked(self):
        self.do_authentication(AuthTestSuiteConfig.register_data1)
        self.add_target(self.target_add_data()) # mandatory, else NoJWTException is raised, should be fixed
        _, _, res = api_add_subdomains(2)
        assert res == 400

    def test_rescan_subdomains_empty(self):
        self.do_authentication(AuthTestSuiteConfig.register_data1)
        # self.add_target(self.target_add_data())
        # self.add_target(self.target_add_data(hostname="borysek.net"))
        res = rescan_subdomains()
        assert res == 0

    def test_rescan_subdomains(self):
        self.do_authentication(AuthTestSuiteConfig.register_data1)
        self.add_target(self.target_add_data())
        self.add_target(self.target_add_data(hostname="borysek.net"))
        api_add_subdomains(1)
        api_add_subdomains(2)
        res = rescan_subdomains()
        assert res == 0

    def test_list_rescan_subdomain_orders(self):
        self.do_authentication(AuthTestSuiteConfig.register_data1)
        self.add_target(self.target_add_data(hostname="borysek.net"))
        api_add_subdomains(1)

        res_list = api_list_domain_monitoring()
        logger.debug(res_list.json)
        assert len(res_list.data)
