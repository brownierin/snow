import os
import configparser
from pathlib import Path
import json
import logging.config
import logging

SNOW_ROOT = os.getcwd()
env = os.getenv("env")
CONFIG = configparser.ConfigParser()
if env == "snow-test":
    CONFIG.read(f"{SNOW_ROOT}/config/test.cfg")
else:
    CONFIG.read(f"{SNOW_ROOT}/config/prod.cfg")


global_exit_code = 0
if CONFIG["general"]["run_local_semgrep"] != "False":
    SNOW_ROOT = CONFIG["general"]["run_local_semgrep"]
LANGUAGES_DIR = SNOW_ROOT + CONFIG["general"]["languages_dir"]
RESULTS_DIR = SNOW_ROOT + CONFIG["general"]["results"]
REPOSITORIES_DIR = SNOW_ROOT + CONFIG["general"]["repositories"]
with open(f"{SNOW_ROOT}/{CONFIG['general']['forked_repos']}") as file:
    FORKED_REPOS = json.load(file)

VERSION = CONFIG["general"]["version"]
DIGEST = CONFIG["general"]["digest"]

CHECKPOINT_API_URL = CONFIG["general"]["checkpoint_api_url"]
TSAUTH_TOKEN_ENV = CONFIG["general"]["tsauth_token_env"]

logging.config.fileConfig(fname=f"{SNOW_ROOT}/config/logging.ini")

commit_head_env = CONFIG["general"]["commit_head"]
master_commit_env = CONFIG["general"]["master_commit"]
artifact_dir_env = CONFIG["general"]["artifact_dir"]
print_text = CONFIG["general"]["print_text"]
high_alert_text = CONFIG["alerts"]["high_alert_text"]
banner = CONFIG["alerts"]["banner"]
normal_alert_text = CONFIG["alerts"]["normal_alert_text"]
no_vulns_text = CONFIG["alerts"]["no_vulns_text"]
errors_text = CONFIG["alerts"]["errors_text"]
ghe_url = CONFIG["general"]["ghe_url"]
ghc_url = "github.com"


def set_enabled_filename():
    if env == "snow-test":
        return "enabled-test"
    else:
        return "enabled"
