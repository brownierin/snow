#!/usr/bin/env python3
# -*- coding: future_fstrings -*-

import requests
import os


def send(content):
    headers = {"Content-Type": "application/json"}
    data = {"text": content}
    url = os.environ.get("SNOW_ALERT_WEBHOOK")

    try:
        r = requests.post(url, headers=headers, json=data)
    except Exception as e:
        raise e

    r.raise_for_status()
    return r
