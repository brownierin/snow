#!/bin/bash

python3 -m pip install wheel
python3 -m pip install -r requirements.txt
export PATH="$HOME/.local/bin:$PATH"
poetry install
python3 -m pytest tests/integration/
