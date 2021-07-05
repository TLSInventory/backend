# Development

This document notes some usefull aproaches for development and debugging.

```bash
sudo apt-get install python3.7-dev graphviz
python3.7 -m pip install -r requirements-dev.txt
```

Nice SVG profiling outputs can be acquired for tests:

```bash
pytest --profile-svg tests/api_retrieval_test.py
```

It's also useful to set configs `config.TestConfig` and also `config.FlaskConfig.SQLALCHEMY_ECHO` from within the tests.
Note that setting variables that are present in `config.py` is persistent across tests run by an invocation of pytest.
The `config.py` is not reloaded each time, so defaults don't get reloaded.



### Tests on big datasets

Some v1 endpoints (primarily scan history) used to have performance problems when the result should have contained thousands of objects. This is mostly solved by v2 API. The one problem, that partially remains, is the fact that it's hard to test it. Parsing thousands of scans would take significant time - much longer than the retrieval. Including a huge preparsed database (>100 MB) to git is not a good idea, so we're using it only localy. Inside tests on github we're doing a trick - we parse a single scan, and then fake the database so that it appears like a thousand scans with the same result. This provides good data for the v1 endpoints which did not do any deduplication, though it does not test well the performance of the new endpoints from v2.

If you want to thourougly test the performance, we suggest that you make a few thousand scan of something, and save the resulting DB. Then inside the file for API tests uncomment line with a path to a existing DB, and use it that way.

## Github Actions

### Automatic tests + profiling + coverage
Each push to any branch triggers `pytest`. As part of pytest, both coverage and profiling information is collected, and uploaded as an artifact. Codecoverage is also uploaded to `codecov`.

### Internal dependency graph

On each push to any branch a workflow creates 3 SVG artifacts containing graph of internal dependencies. One version is black-white, one is colored based on the file that contains the include directive, and the last one is colored based on the file that is being included.

### Auto-increase version.txt
Each push to branch `integration` triggers action that increases the version inside `version.txt`. This means that while we don't strictly follow semantic versioning (and we won't until we're out of beta), at least each version deployed a test server or production has a unique version id.

## Other automatization

### Docker Hub

Push to `master` or `integration` triggers Docker image build (and release) on Docker Hub. Production periodically checks if new version of tag `latest` (branch `master`) is available and if it is, the image is downloaded and app restarted to the new version.
