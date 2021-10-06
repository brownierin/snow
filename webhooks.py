#!/usr/bin/env python3
# -*- coding: future_fstrings -*-

import requests
import os


def send(content):
    headers = {"Content-Type": "application/json"}
    data = {"text": content}

    try: 
        length = len(os.environ.get("SNOW_ALERT_WEBHOOK"))
        print(f"[+] The webhook url length is: {length}")
    except Exception as e:
        print("[+] The webhook url length is 0")

    try:
        length = len(os.environ.get("CHECKPOINT_TOKEN"))
        print(f"[+] The checkpoint token length is: {length}")
    except Exception as e:
        print("[+] The checkpoint token length is 0")

    try:
        length = len(os.environ.get("TEST"))
        print(f"[+] The test token length is: {length}")
    except Exception as e:
        print("[+] The test token length is 0")

    try: 
        url = os.environ["SNOW_ALERT_WEBHOOK"]
    except Exception as e:
        print(f"[-] Webhook URL isn't set! Error is: {e}")

    try:
        r = requests.post(url, headers=headers, json=data)
    except Exception as e:
        raise e

    r.raise_for_status()
    return r
