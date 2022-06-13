#!/bin/bash

pip3 install -r requirements.txt
poetry install
poetry run python3 -m pytest tests/unit/
