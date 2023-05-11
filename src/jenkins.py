#!/usr/bin/env python3

import os
import logging

from src.config import JENKINS_PROD_JOB
from src.config import logger


def get_ci_env():
    if "JOB_NAME" in os.environ:
        return "jenkins"
    elif "GITHUB_ACTION" in os.environ:
        return "github actions"
    else:
        return


def get_job_name():
    if "JOB_NAME" in os.environ:
        return os.environ["JOB_NAME"]
    return "local"


def get_job_enviroment():
    job_name = get_job_name()

    # This case happens when we aren't running on Jenkins
    if job_name == "local":
        return "dev"

    # This case happens when we are running on the production job on Jenkins
    if job_name.lower() == JENKINS_PROD_JOB.lower():
        return "prod"

    # This case happens when we are running a job on Jenkins, but it it's the
    # production job.
    return "qa"
