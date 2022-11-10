#!/usr/bin/env python3

import logging
import os

import src.verify as verify
from src.util import *
from src.config import *
import src.git as git


# verify.get_docker_image()
# verify.build_dockerfile()
# verify.build_container()

docker_base_string = f"docker run -t -v {SNOW_ROOT}:/src slack/semgrep poetry run /src/run_semgrep.py"

# daily
git.download_repos()
run_long_command(f"{docker_base_string} -m daily")

# pr
# repo_long = "slack-github.com/slack/fake_repo"
# git.git_ops_pr_scan(repo_long)
# run_long_command(f"{docker_base_string} -m pr -r {repo_long}")

