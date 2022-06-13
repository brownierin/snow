#!/bin/bash

python3 -m pip install wheel
python3 -m pip install -r requirements.txt
poetry install
poetry run python3 -m pytest tests/integration/
