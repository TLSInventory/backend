import json

import tests.conftest
import pytest
from flask import url_for


@pytest.mark.usefixtures('client_class')
class TestSuiteCriticalPath:
    def register_data1(self):
        return {
            'username': 'lorem',
            'password': 'ipsum',
            'email': 'dolor@sit.amet'
        }

    def login_data1(self):
        return {
            'username': 'lorem',
            'password': 'ipsum',
        }

    def url_login(self):
        return url_for("apiV1.api_login")

    def url_register(self):
        return url_for("apiV1.api_register")

    def url_add_target(self):
        return url_for("apiV1.api_target")

    def target_data(self):
        return {
            "target": {
                "hostname": "example.com",
                "port": 443,
                "ip_address": "127.0.0.1",
                "protocol": "HTTPS"
            }
        }

    def url_list_targets(self):
        return url_for("apiV1.api_get_user_targets")

    def url_access_cookie(self):
        return url_for("apiDebug.debugSetAccessCookie")

    def test_critical_path1(self):
        assert self.client.post(self.url_register(), json=self.register_data1()).status_code == 200
        assert self.client.post(self.url_login(), json=self.login_data1()).status_code == 200
        assert self.client.get(self.url_access_cookie()).status_code == 200
        assert self.client.put(self.url_add_target(), json=self.target_data()).status_code == 200

        targets = self.client.get(self.url_list_targets())
        assert targets.status_code == 200

        # todo: enable this check
        # targets_json: dict = json.loads(targets.data)
        # assert len(targets_json) == 1


