import requests
import os


def send_webhook(content):
    headers = {"Content-Type: application/json"}
    data = {"text": content}
    url = os.environ.get("SNOW_ALERT_WEBHOOK")

    try:
        r = requests.post(url, headers=headers, data=data)
    except Exception as e:
        raise e

    r.raise_for_status()
