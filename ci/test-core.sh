#!/bin/bash

pip3 install -r requirements.txt
export PATH="$HOME/.poetry/bin:$HOME/.local/bin:$PATH"
poetry install
poetry run python3 -m pytest tests/unit/
