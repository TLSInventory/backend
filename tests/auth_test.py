import tests.conftest
import pytest
from flask import url_for


class TestSuiteConfig:
    @staticmethod
    def url_login():
        return url_for("apiV1.api_login")

    @staticmethod
    def url_register():
        return url_for("apiV1.api_register")

    register_data1 = {
        'username': 'lorem',
        'password': 'ipsum',
        'email': 'dolor@sit.amet'
    }

    register_data2 = {
        'username': 'lorem2',
        'password': 'ipsum',
        'email': 'dolor@sit.amet'
    }

    @staticmethod
    def login_data_from_register(registration_data: dict):
        answer = registration_data.copy()
        del answer['email']
        return answer


def register(func):
    def wrapper(self):
        assert self.client.post(TestSuiteConfig.url_register(), json=TestSuiteConfig.register_data1).status_code == 200
        func(self)
    return wrapper


def login(func):
    def wrapper(self):
        assert self.client.post(
            TestSuiteConfig.url_login(),
            json=TestSuiteConfig.login_data_from_register(TestSuiteConfig.register_data1)
        ).status_code == 200
        func(self)
    return wrapper


def register_and_login(func):
    @register
    @login
    def wrapper(self):
        func(self)
    return wrapper


def set_debug_access_cookie(func):
    def wrapper(self):
        assert self.client.get(url_for("apiDebug.debugSetAccessCookie")).status_code == 200
        func(self)
    return wrapper


@pytest.mark.usefixtures('client_class')
class TestSuiteAuth:

    def test_login_no_auth(self):
        assert self.client.post(TestSuiteConfig.url_login()).status_code == 400

    def test_login_bad_auth(self):
        assert self.client.post(
            TestSuiteConfig.url_login(),
            json=TestSuiteConfig.login_data_from_register(TestSuiteConfig.register_data1)
        ).status_code == 401

    @register
    def test_register_one(self):
        # asserts in the decorator itself
        pass

    @register
    def test_register_two(self):
        # asserts in the decorator itself
        assert self.client.post(TestSuiteConfig.url_register(), json=TestSuiteConfig.register_data2).status_code == 200

    @register
    def test_register_duplicate(self):
        assert self.client.post(TestSuiteConfig.url_register(), json=TestSuiteConfig.register_data1).status_code == 400

    @register_and_login
    def test_register_login(self):
        # asserts in the decorator itself
        pass

    @register_and_login
    def test_login_with_unregistered_user(self):
        assert self.client.post(
            TestSuiteConfig.url_login(),
            json=TestSuiteConfig.login_data_from_register(TestSuiteConfig.register_data2)
        ).status_code == 401


# app_inst = app_test_instance()

