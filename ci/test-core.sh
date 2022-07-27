#!/bin/bash

pip3 install -r requirements.txt
python3 -m poetry install
python3 -m pytest tests/unit/
