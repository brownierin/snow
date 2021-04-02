#!/bin/bash

pip3 install virtualenv
[ ! -d "env" ] && python3 -m virtualenv env
source env/bin/activate
pip3 install -r requirements.txt
