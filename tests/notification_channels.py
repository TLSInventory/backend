import pytest
from flask import url_for

import config
from tests.auth_test import AuthTestSuiteConfig

@pytest.mark.usefixtures('client_class')
class TestNotificationChannels:

    def do_authentication(self, registration_data: dict):
        assert self.client.post(url_for("apiV1.api_register"), json=registration_data).status_code == 200
        assert self.client.post(url_for("apiV1.api_login"), json=AuthTestSuiteConfig.login_data_from_register(registration_data)).status_code == 200
        assert self.client.get(url_for("apiDebug.debugSetAccessCookie")).status_code == 200

    @pytest.mark.regression
    @pytest.mark.skipif(config.MailConfig.check_refresh_cookie_on_validating_email, reason="This test only make sense if JWT token is required for mail validation.")
    def test_mail_validation_code_doesnt_require_jwt(self):
        res = self.client.get(url_for('apiDebug.mail_validate', db_code='random_string'))
        assert res != 401

