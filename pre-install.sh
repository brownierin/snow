#!/bin/bash

set +x

[ ! -d "env" ] && python3.5 -m venv env -
source env/bin/activate
pip3 install -r requirements.txt
