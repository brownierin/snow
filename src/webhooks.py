#!/usr/bin/env python3

import requests
import os
import logging
from src.exceptions import WebhookUrlError

logging.getLogger(__name__)


def send(content):
    headers = {"Content-Type": "application/json"}
    data = {"text": content}

    try:
        url = os.environ["SNOW_ALERT_WEBHOOK"]
    except KeyError as e:
        logging.exception(f"Webhook URL isn't set! Error is: {e}")
        raise WebhookUrlError

    try:
        r = requests.post(url, headers=headers, json=data)
    except Exception as e:
        raise e

    r.raise_for_status()
    return r
