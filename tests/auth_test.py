import tests.conftest
import pytest
from flask import url_for


@pytest.mark.usefixtures('client_class')
class TestSuiteAuth:

    def register_data1(self):
        return {
            'username': 'lorem',
            'password': 'ipsum',
            'email': 'dolor@sit.amet'
        }

    def register_data2(self):
        return {
            'username': 'lorem2',
            'password': 'ipsum',
            'email': 'dolor@sit.amet'
        }

    def login_data1(self):
        return {
            'username': 'lorem',
            'password': 'ipsum',
        }

    def login_data2(self):
        return {
            'username': 'lorem2',
            'password': 'ipsum',
        }

    def url_login(self):
        return url_for("apiV1.api_login")

    def url_register(self):
        return url_for("apiV1.api_register")

    def test_login_no_auth(self):
        assert self.client.post(self.url_login()).status_code == 400

    def test_login_bad_auth(self):
        assert self.client.post(self.url_login(), json=self.login_data1()).status_code == 401

    def test_register_one(self):
        assert self.client.post(self.url_register(), json=self.register_data1()).status_code == 200

    def test_register_two(self):
        assert self.client.post(self.url_register(), json=self.register_data1()).status_code == 200
        assert self.client.post(self.url_register(), json=self.register_data2()).status_code == 200

    def test_register_duplicate(self):
        assert self.client.post(self.url_register(), json=self.register_data1()).status_code == 200
        assert self.client.post(self.url_register(), json=self.register_data1()).status_code == 400

    def test_register_login(self):
        assert self.client.post(self.url_register(), json=self.register_data1()).status_code == 200
        assert self.client.post(self.url_login(), json=self.login_data1()).status_code == 200
        assert self.client.post(self.url_login(), json=self.login_data2()).status_code == 401


# app_inst = app_test_instance()

