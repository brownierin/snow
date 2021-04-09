#!/bin/bash

set +x

# fix ensurepip error
export LC_ALL="en_US.UTF-8"
export LC_CTYPE="en_US.UTF-8"
sudo dpkg-reconfigure locales

[ ! -d "env" ] && python3 -m venv env
source env/bin/activate
pip3 install -r requirements.txt
