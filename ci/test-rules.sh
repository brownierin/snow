#!/bin/bash

pip3 install -r requirements.txt

./tests/rules/run_tests.py --generate_checkpoint_artifact --worker=4
