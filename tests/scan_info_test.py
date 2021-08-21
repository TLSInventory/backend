import pytest
import config
import app.db_models as db_models


from app.views.v2.scan_info_utils import get_general_scan_info, get_user_scan_info
from flask import url_for


# change default db
# config.TestConfig.force_database_connection_string = "/Users/krebso/Downloads/db/db_2021"


@pytest.mark.usefixtures("client_class")
class TestSuiteScanScheduler:

    @classmethod
    def teardown_class(cls):
        config.TestConfig.force_database_connection_string = None

    def add_target(self, json_data):
        # adding a target without IP will result
        # in DNS query on every enque for scan
        res = self.client.put(url_for("apiV1.api_target"), json=json_data)
        assert res.status_code == 200
        return res

    def test_general_scan_info_endpoint(self):
        res, out = get_general_scan_info()
        assert res == 200
        print(out)

    def test_user_scan_info_endpoint(self):
        users = db_models.db.session.query(db_models.User).all()
        uids = list(map(lambda x: x.id, users))

        for uid in uids:
            res, out = get_user_scan_info(user_id=uid, days_back=500)
            assert res == 200
            print(out)
