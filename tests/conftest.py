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
class TestSuiteExample:

    def test_myview(self):
        url = url_for("apiDebug.debug_connecting_ip")
        # url = '/api/debug/connecting_ip'
        assert self.client.get(url).status_code == 200


