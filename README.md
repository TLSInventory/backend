# TLSInventory - backend

![Tests: master](https://img.shields.io/github/workflow/status/TLSInventory/backend/requirements-and-pytest/master)
[![codecov](https://codecov.io/gh/TLSInventory/backend/branch/master/graph/badge.svg?token=6VJCYR33LN)](https://codecov.io/gh/TLSInventory/backend)
![Python versions](https://img.shields.io/badge/Python%20versions-3.7-green)

This is backend of application [TLSInventory](https://github.com/TLSInventory).

This section serves as the main API server and also contains all the scanners.
Sensors are deployed as instances of this repository, with a different entrypoint.

For information how to deploy this application check the [Docker repository](https://github.com/TLSInventory/Docker).

# Backend requirements 

Exactly Python 3.7.x is required until I upgrade to SSLyze 3.*
Python packages are listed in file `requirements.txt`.


#### Integration branch

![Tests: integration](https://img.shields.io/github/workflow/status/TLSInventory/backend/requirements-and-pytest/integration)
[![codecov](https://codecov.io/gh/TLSInventory/backend/branch/integration/graph/badge.svg?token=6VJCYR33LN)](https://codecov.io/gh/TLSInventory/backend)

Todo: add version support indicator
Todo: add test status indicator
