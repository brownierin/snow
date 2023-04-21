#!/bin/bash

pip3 install -r requirements.txt
poetry install

poetry run $(pwd)/tests/rules/run_tests.py --generate_checkpoint_artifact --worker=4
