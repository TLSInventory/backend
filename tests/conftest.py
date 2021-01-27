import pytest
import string
import random
from flask import url_for
import os
import tempfile
import datetime

# basedir = os.path.abspath(os.path.dirname(__file__))

# The following approach will require the environ to be set before config file is imported.
# Setting up from environ is one time thing.
# os.environ['SQLALCHEMY_DATABASE_URI'] = '/mnt/c/Github/tlsinventory/backend' + '/db/auto_tests.db'
# from app import create_app

# from ../app import create_app
import app as app2

# https://docs.pytest.org/en/latest/example/simple.html#making-test-result-information-available-in-fixtures
@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    # execute all other hooks to obtain the report object
    outcome = yield
    rep = outcome.get_result()

    # set a report attribute for each phase of a call, which can
    # be "setup", "call", "teardown"

    setattr(item, "rep_" + rep.when, rep)


@pytest.fixture
def app(request):
    import config
    timestamp = int(datetime.datetime.now().timestamp())
    testname = request.node.name

    # todo: maybe use in-memory DB
    db_handle, db_filename = tempfile.mkstemp(prefix=f'tlsinventory_{timestamp}_{testname}_', suffix='.db')
    # print(db_filename)
    config.FlaskConfig.SQLALCHEMY_DATABASE_URI = 'sqlite:///' + db_filename

    app = app2.create_app()
    # app.run(host='127.0.0.1', port=5042)

    yield app

    os.close(db_handle)

    delete_tmp_db = True

    # https://docs.pytest.org/en/latest/example/simple.html#making-test-result-information-available-in-fixtures
    if request.node.rep_setup.failed:
        print("setting up a test failed!", request.node.nodeid)
    elif request.node.rep_setup.passed:
        if request.node.rep_call.failed:
            # print("executing test failed", request.node.nodeid)
            delete_tmp_db = False

    if delete_tmp_db:
        os.unlink(db_filename)


# todo: add fixture with registration, login and set_cookie

@pytest.mark.usefixtures('client_class')
class TestSuiteExample:

    def test_myview(self):
        url = url_for("apiDebug.debug_connecting_ip")
        # url = '/api/debug/connecting_ip'
        assert self.client.get(url).status_code == 200


