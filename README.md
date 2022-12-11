# TLSInventory

![Test status: master](https://img.shields.io/github/workflow/status/TLSInventory/backend/requirements-and-pytest/master)
[![codecov](https://codecov.io/gh/TLSInventory/backend/branch/master/graph/badge.svg?token=6VJCYR33LN)](https://codecov.io/gh/TLSInventory/backend)
![Python versions](https://img.shields.io/badge/Python%20versions-3.7-green)

We aim to provide self-hosted tool that would allow for monitoring of (sub)domains for HTTPS certificate expiration, changes in TLS settings and notify in case of any problems or even proactively several days ahead, if technically possible.

# Is TLSInventory right for me?

Fairly recently the TLS configuration monitoring has become standard and many other projects are better suited for some specific use-cases:

- System administrator (warning about upcoming certificate expiration) - e.g. [Uptime Kuma](https://github.com/louislam/uptime-kuma)
- Detailed TLS monitoring with output to JSON (including "grade") - [SSLyze](https://github.com/nabla-c0d3/sslyze) (since version 5.0)

### We still have some unique features

- Extremely efficient data storage for large volume of scans
    - Scanning 1 million domains using SSLyze takes ~250 GB, TLSInventory deduplicates that data to ~50 GB
    - Running the same scan twice, SSLyze would have ~500 GB, TLSInventory ~50.7 GB.
- Data can be queried using SQL!

If you are only interested in backend and are not afraid to interact with SQLite database, it can be a great tool for research purposeses as it can acquire complete TLS configuration for tens of thousands of websites per day and very efficiently store it in SQL database.

# Backend

This repository contains the backend of application [TLSInventory](https://github.com/TLSInventory).

This part serves as the main API server and also contains all the scanners.
Sensors are deployed as instances of this repository, with a different entrypoint.

For information how to deploy this application check the [Docker repository](https://github.com/TLSInventory/Docker).

#### Requirements 

Exactly Python 3.7.x is required - a limitation due to a dependency on SSLyze v2.6.
Python packages are listed in file `requirements.txt`.

```bash
python3.7 -m venv .venv
source .venv/bin/activate
python3.7 -m pip install -r requirements.txt
# python3.7 -m pip install -r requirements-dev.txt # Run this if you want to run tests, or develop the source code.
```


## Development

For information about development practices see file [Development.md](Development.md)

#### Integration (main development) branch

![Test status: integration](https://img.shields.io/github/workflow/status/TLSInventory/backend/requirements-and-pytest/integration)
[![codecov](https://codecov.io/gh/TLSInventory/backend/branch/integration/graph/badge.svg?token=6VJCYR33LN)](https://codecov.io/gh/TLSInventory/backend)

