#!/bin/bash

pip3 install -r requirements.txt
poetry install
python3 -m pytest tests/unit/
