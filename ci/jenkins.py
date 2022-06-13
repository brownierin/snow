#!/usr/bin/env python3


import os
import configparser


env = os.getenv("env")
CONFIG = configparser.ConfigParser()
if env == "test":
    CONFIG.read('config/test.cfg')
else:
    CONFIG.read('config/prod.cfg')


def get_job_name():
    if "JOB_NAME" in os.environ:
        return os.environ['JOB_NAME']
    return "local"


def get_job_enviroment():
    job_name = get_job_name()

    # This case happens when we aren't running on Jenkins
    if job_name == "local":
        return "dev"

    # This case happens when we are running on the production job on Jenkins
    if job_name.lower() == CONFIG['general']['jenkins_prod_job'].lower():
        return "prod"

    # This case happens when we are running a job on Jenkins, but it it's the
    # production job.
    return "qa"
