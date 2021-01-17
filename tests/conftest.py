import pytest
import string
import random
from flask import url_for

# basedir = os.path.abspath(os.path.dirname(__file__))

# The following approach will require the environ to be set before config file is imported.
# Setting up from environ is one time thing.
# os.environ['SQLALCHEMY_DATABASE_URI'] = '/mnt/c/Github/tlsinventory/backend' + '/db/auto_tests.db'
# from app import create_app

from app import create_app


@pytest.fixture
def app():
    import config

    db_random = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    db_filename = '/mnt/c/Github/tlsinventory/backend' + f'/tmp/tests_{db_random}.db'
    config.FlaskConfig.SQLALCHEMY_DATABASE_URI = 'sqlite:///' + db_filename

    app = create_app()
    # app.run(host='127.0.0.1', port=5042)

    return app


@pytest.mark.usefixtures('client_class')
class TestSuite:

    def test_myview(self):
        url = url_for("apiDebug.debug_connecting_ip")
        # url = '/api/debug/connecting_ip'
        assert self.client.get(url).status_code == 200


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

