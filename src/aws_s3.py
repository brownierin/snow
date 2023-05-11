#!/usr/bin/env python3

import logging

import boto3

from src.config import logger


def upload_file(filename, bucket):
    s3_client = boto3.client("s3")
    try:
        # We'll use the filename as the object_name
        logging.info(f"Uploading file {filename}")
        res = s3_client.upload_file(
            filename, bucket, filename, ExtraArgs={"Metadata": {"key": "value", "ACL": "private"}}
        )
    except boto3.ClientError as e:
        logging.error(f"Failed to upload file")
        return False
    logging.info(f"Uploaded file successfully")
    return True


def upload_files(filenames, bucket):
    for filename in filenames:
        upload_file(filename, bucket)
