## Development

This document notes some usefull aproaches for development and debugging.

```bash
sudo apt-get install python3.7-dev
python3.7 -m pip install -r requirements-dev.txt
```

Nice SVG profiling outputs can be acquired for tests:

```bash
pytest --profile-svg tests/api_retrieval_test.py
```

It's also useful to set configs `config.TestConfig` and also `config.FlaskConfig.SQLALCHEMY_ECHO` from within the tests.
Note that setting variables that are present in `config.py` is persistent across tests run by an invocation of pytest.
The `config.py` is not reloaded each time, so defaults don't get reloaded.
