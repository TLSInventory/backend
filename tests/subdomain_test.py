from typing import Optional

import pytest
from flask import url_for


@pytest.mark.usefixtures('client_class')
class TestSuiteAddSubdomains:

    def __register_data1(self):
        return {
            'username': 'pls',
            'password': 'addsubdomains',
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

    def __target_add_data(self, hostname:str ="is.muni.cz", ip: Optional[str]=None):
        return {
            "target": {"id": None, "hostname": hostname, "port": None, "ip_address": ip, "protocol": "HTTPS"},
            "scanOrder": {"periodicity": 43200, "active": None}
         }

    def __add_target(self, json_data):
        # adding a target without IP will result in DNS query on every enque for scan
        res = self.client.put(url_for("apiV1.api_target"), json=json_data)
        assert res.status_code == 200
        return res

    def __add_subdomains(self):
        res = self.client.post(url_for("apiV1.api_add_subdomain"))
        assert res.status_code == 200