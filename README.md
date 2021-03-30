# TLSInventory

![Test status: master](https://img.shields.io/github/workflow/status/TLSInventory/backend/requirements-and-pytest/master)
[![codecov](https://codecov.io/gh/TLSInventory/backend/branch/master/graph/badge.svg?token=6VJCYR33LN)](https://codecov.io/gh/TLSInventory/backend)
![Python versions](https://img.shields.io/badge/Python%20versions-3.7-green)
![Alpha status](https://img.shields.io/badge/-Alpha-orange)

We aim to provide self-hosted tool that would allow for monitoring of (sub)domains for HTTPS certificate expiration, changes in TLS settings and notify in case of any problems or even proactively several days ahead, if technically possible.

#### Current status

We hope to (in due time) make this tool a worthy rival to ssllabs and to services that monitor websites for TLS problems. However, we're not there yet. We will for example need to

- rework the API (users with too many (sub)domains are getting unusably big API responses - they might even timeout)
- solve a few potential circular dependency problems
- speed-up the import of scan results
- improve the test coverage
- significantly improve the frontend (web interface) - we are currently presenting only a small fraction of the information that is being collected

We currently don't recommend using this project as the sole tool used for monitoring. Though adding it to your suite of tools might be a worthy inclusion (if you don't have too many (sub)domains (see bug above)).

If you are only interested in backend and are not afraid to interact with SQLite database, it can be a great tool for research purposeses as it can acquire complete TLS configuration for tens of thousands of websites per day and very efficiently store it in SQL database.

# Backend

This repository contains the backend of application [TLSInventory](https://github.com/TLSInventory).

This part serves as the main API server and also contains all the scanners.
Sensors are deployed as instances of this repository, with a different entrypoint.

For information how to deploy this application check the [Docker repository](https://github.com/TLSInventory/Docker).

#### Requirements 

Exactly Python 3.7.x is required until we upgrade to SSLyze 3.*
Python packages are listed in file `requirements.txt`.


#### Integration (main development) branch

![Test status: integration](https://img.shields.io/github/workflow/status/TLSInventory/backend/requirements-and-pytest/integration)
[![codecov](https://codecov.io/gh/TLSInventory/backend/branch/integration/graph/badge.svg?token=6VJCYR33LN)](https://codecov.io/gh/TLSInventory/backend)

