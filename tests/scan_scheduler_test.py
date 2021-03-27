from typing import Optional

import pytest
from datetime import datetime, timedelta
from app.utils.time_helper import time_source
from flask import url_for
from config import SchedulerConfig


@pytest.mark.usefixtures('client_class')
class TestSuiteScanScheduler:
    SMALL_OFFSET = timedelta(seconds=10)  # seconds

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

    def __target_add_data(self, hostname:str ="example.com", ip: Optional[str]=None):
        return {
            "target": {"id": None, "hostname": hostname, "port": None, "ip_address": ip, "protocol": "HTTPS"},
            "scanOrder": {"periodicity": 43200, "active": None}
         }

    def __add_target(self, json_data):
        # adding a target without IP will result in DNS query on every enque for scan
        res = self.client.put(url_for("apiV1.api_target"), json=json_data)
        assert res.status_code == 200
        return res

    def __enable_time_mocking(self):
        time_source.mock(True)
        time_source.set_now()

    def test_added_target_with_static_ip_appears_in_scheduler(self):
        self.__add_target_and_check_presence_in_batch(True)

    @pytest.mark.skip(reason="Dnspython 2.0 has deprecated some functions. Fix later.")
    def test_added_target_with_dns_appears_in_scheduler(self):
        # this test needs working DNS for example.com
        # todo: library dnspython updated and deprecated the way our DNS is handled.
        self.__add_target_and_check_presence_in_batch(False)

    def __add_target_and_check_presence_in_batch(self, static_ip=True):
        self.__enable_time_mocking()
        self.__do_authentication()

        ip = "127.0.0.1" if static_ip else None
        self.__add_target(self.__target_add_data(ip=ip))

        time_source.offset_time(timedelta(seconds=SchedulerConfig.max_first_scan_delay) + self.SMALL_OFFSET)

        res = self.client.get(url_for("apiV1.api_get_next_targets_batch"))
        assert res.status_code == 200
        assert len(res.json)>0

    def test_requeuing_after_min_separation(self):
        self.__enable_time_mocking()
        self.__do_authentication()

        self.__add_target(self.__target_add_data(ip="127.0.0.1"))
        time_source.offset_time(timedelta(seconds=SchedulerConfig.max_first_scan_delay) + self.SMALL_OFFSET)

        # Scan should be requeued if it did not finish and some time has passed
        for i in range(10):
            time_source.offset_time(timedelta(seconds=SchedulerConfig.enqueue_min_time) + self.SMALL_OFFSET)
            res = self.client.get(url_for("apiV1.api_get_next_targets_batch"))
            assert res.status_code == 200
            assert len(res.json)>0

    def test_not_requeuing_right_away(self):
        self.__enable_time_mocking()
        self.__do_authentication()

        self.__add_target(self.__target_add_data(ip="127.0.0.1"))
        time_source.offset_time(timedelta(seconds=SchedulerConfig.max_first_scan_delay) + self.SMALL_OFFSET)

        # First batch should get the target
        res = self.client.get(url_for("apiV1.api_get_next_targets_batch"))
        assert res.status_code == 200
        assert len(res.json) > 0

        # The second batch shouldn't get the target, because it was enqueud recently
        res = self.client.get(url_for("apiV1.api_get_next_targets_batch"))
        assert res.status_code == 200
        assert len(res.json) == 0








