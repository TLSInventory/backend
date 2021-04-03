#!/bin/bash

# This should be run from the root of the repository.

mkdir -p tmp

grep -r -i --include \*.py "import" ./app/ |  cut -c 3- | grep "app." > tmp/imports.log

# # This also requires both the graphviz package and the graphviz pip package.
# sudo apt install graphviz
# python3 -m pip install --user graphviz

python3 tests/imports/parse_imports.py
