#!/usr/bin/env python3

import requests
import os
import logging

from src.exceptions import WebhookUrlError
from src.config import logger


def send(content):
    headers = {"Content-Type": "application/json"}
    data = {"text": content}

    url = os.environ.get("SNOW_ALERT_WEBHOOK")
    if url is None:
        logging.exception(f"Webhook URL isn't set!")
        raise WebhookUrlError

    try:
        r = requests.post(url, headers=headers, json=data)
    except Exception as e:
        raise e

    r.raise_for_status()
    return r
