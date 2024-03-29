import json

import tests.conftest
import pytest
from flask import url_for
from tests.auth_test import login, register, set_debug_access_cookie

@pytest.mark.usefixtures('client_class')
class TestSuiteCriticalPath:
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

    def target_add_data(self):
        return {
            "target": {"id": None, "hostname": "test2.example.com", "port": None, "ip_address": None, "protocol": "HTTPS"},
            "scanOrder": {"periodicity": 43200, "active": None}
         }

    def url_list_targets(self):
        return url_for("apiV1.api_get_user_targets")

    @register
    @login
    @set_debug_access_cookie
    def test_critical_path1(self):
        # todo: the target_data should be sufficient, but currently only targets with scan_order are being returned. fix that
        # assert self.client.put(self.url_add_target(), json=self.target_data()).status_code == 200
        assert self.client.put(self.url_add_target(), json=self.target_add_data()).status_code == 200

        targets = self.client.get(self.url_list_targets())
        assert targets.status_code == 200

        targets_json: dict = json.loads(targets.data)
        assert len(targets_json) == 1

        assert self.client.get(url_for('apiV1.api_notification_settings')).status_code == 200
        assert self.client.get(url_for('apiV1.api_notification_settings', target_id=1)).status_code == 200




