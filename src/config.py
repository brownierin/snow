import os
import configparser
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

HIGH_ALERT_TEXT = CONFIG["alerts"]["high_alert_text"]
BANNER = CONFIG["alerts"]["banner"]
NORMAL_ALERT_TEXT = CONFIG["alerts"]["normal_alert_text"]
NO_VULNS_TEXT = CONFIG["alerts"]["no_vulns_text"]
ERRORS_TEXT = CONFIG["alerts"]["errors_text"]

commit_head_env = CONFIG["general"]["commit_head"]
master_commit_env = CONFIG["general"]["master_commit"]
artifact_dir_env = CONFIG["general"]["artifact_dir"]
print_text = CONFIG["general"]["print_text"]
ghe_url = CONFIG["general"]["ghe_url"]
ghc_url = "github.com"
global_exit_code = 0


def set_enabled_filename():
    if env == "snow-test":
        return "enabled-test"
    else:
        return "enabled"
