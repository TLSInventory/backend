import sqlalchemy.orm
from flask import url_for
import pytest
import config

import app.db_models as db_models
from tests.auth_test import register_direct, login_direct, access_cookie_direct
import tests.sslyze_parse_test as sslyze_parse_test

@pytest.mark.usefixtures('client_class')
class TestSuiteAPIDataRetrieval:

    @staticmethod
    def __do_authentication(client):
        register_direct(client)
        login_direct(client)
        access_cookie_direct(client)

    @staticmethod
    def url_get_history():
        return url_for("apiV1.api_scan_result_history")


    def get_history_and_save_json_to_file(self, filename: str):
        targets = self.client.get(self.url_get_history())
        assert targets.status_code == 200

        with open(filename, "wb") as f:
            f.write(targets.data)

    def test_get_history_on_new_db(self, freezer):

        sslyze_parse_test.TestSuiteSSLyzeParse().parse_and_save_to_database_x_times(self.client, freezer, 2)

        self.get_history_and_save_json_to_file("tmp/test5a.json")

        for i in range(1, 8000):
            x = db_models.ScanResultsHistory.query.get(2)
            db_models.db.session.expunge(x)
            sqlalchemy.orm.make_transient(x)
            x.id = None
            x.timestamp += i
            db_models.db.session.add(x)

        db_models.db.session.commit()

        self.get_history_and_save_json_to_file("tmp/test5b.json")

