#!/bin/sh

set -e

cp db/test.db db/backup_before_startup_timestamp_`date +%s`_version_`cat version.txt`.db
flask db upgrade
python3.7 start.py
