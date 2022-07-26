#!/bin/bash

set +x

pip3 install -r requirements.txt
poetry update
poetry install --no-dev
