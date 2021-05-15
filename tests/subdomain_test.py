from typing import Optional

import pytest
from flask import url_for

from app.views.v1.subdomain_util import api_add_subdomains


class ModuleTester:

    def register_data1(self):
        return {
            'username': 'pls',
            'password': 'addsubdomains',
            'email': 'dolor@sit.amet'
        }

    def login_data_from_register(self, registration_data: dict):
        answer = registration_data.copy()
        del answer['email']
        return answer

    def do_authentication(self):
        assert self.client.post(url_for("apiV1.api_register"), json=self.register_data1()).status_code == 200
        assert self.client.post(url_for("apiV1.api_login"), json=self.login_data_from_register(self.register_data1())).status_code == 200
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


def pytest_configure():
    pytest.first_batch = 0


@pytest.mark.usefixtures('client_class')
class TestSubdomainSuite(ModuleTester):

    def test_add_subdomains(self):
        super().do_authentication()
        super().add_target(super().target_add_data())
        _, fb, res = api_add_subdomains(1)
        assert res == 200
        pytest.first_batch = fb

    def test_same_subdomain_different_user(self):
        super().do_authentication()
        super().add_target(super().target_add_data())
        _, fb, res = api_add_subdomains(1)
        assert res == 200
        assert fb == pytest.first_batch

    def test_repeatedly_add_subdomains(self):
        super().do_authentication()
        super().add_target(super().target_add_data())
        _, _, res = api_add_subdomains(1)
        assert res == 200
        _, added, res = api_add_subdomains(1)
        assert res == 200
        assert added == 0
