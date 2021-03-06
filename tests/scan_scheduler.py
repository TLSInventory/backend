import pytest
from datetime import datetime, timedelta
from app.utils.time_helper import time_source
from flask import url_for
from config import SchedulerConfig



@pytest.mark.usefixtures('client_class')
class TestSuiteScanScheduler:

    def __register_data1(self):
        return {
            'username': 'lorem',
            'password': 'ipsum',
            'email': 'dolor@sit.amet'
        }

    def __login_data_from_register(self, registration_data: dict):
        answer = registration_data.copy()
        del answer['email']
        return answer

    def __do_authentication(self):
        assert self.client.post(url_for("apiV1.api_register"), json=self.__register_data1()).status_code == 200
        assert self.client.post(url_for("apiV1.api_login"), json=self.__login_data_from_register(self.__register_data1())).status_code == 200
        assert self.client.get(url_for("apiDebug.debugSetAccessCookie")).status_code == 200

    def __target_add_data(self):
        return {
            "target": {"id": None, "hostname": "test2.example.com", "port": None, "ip_address": None, "protocol": "HTTPS"},
            "scanOrder": {"periodicity": 43200, "active": None}
         }

    def __add_target(self):
        assert self.client.put(url_for("apiV1.api_target"), json=self.__target_add_data()).status_code == 200

    def test_basic_scheduler_time_mocking_example(self):
        time_source.mock(True)
        time_source.set_now()
        self.__do_authentication()
        self.__add_target()

        time_source.offset_time(timedelta(seconds=SchedulerConfig.max_first_scan_delay + 10))

        assert self.client.get(url_for("apiV1.api_sslyze_scan_due_targets_via_sensor_key")).status_code == 200




