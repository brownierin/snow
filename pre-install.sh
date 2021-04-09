#!/bin/bash

set +x

# install python3-venv so ensurepip is available
apt-get install python3-venv
[ ! -d "env" ] && python3 -m venv env
source env/bin/activate
pip3 install -r requirements.txt
