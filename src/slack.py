#!/usr/bin/env python3


import os
import sys
import logging

import src.util as util
from src.config import logger


def is_webapp(repo):
    return True if repo == "webapp" else False


def slack_repo(repo, git_repo, repo_path, repo_dir):
    if not os.path.isdir(repo_path):
        sys.exit(
            "[!!] webapp not found. Please run clone manually if running locally."
            f" Perhaps\n     with: GIT_LFS_SKIP_SMUDGE=1 git -C {repo_dir}"
            f" clone {git_repo} --depth 1"
        )
    logging.info(f"Updating repo: {repo}")
    command = f"git -C {repo_path} fetch --tags --force --progress -- {git_repo} +refs/heads/*:refs/remotes/origin1/*"
    process = util.run_command(command)


def commit_head(url):
    if url == "github.com":
        os.environ["CIBOT_COMMIT_HEAD"] = os.environ.get("GITHUB_SHA")
