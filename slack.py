#!/usr/bin/env python3
# -*- coding: future_fstrings -*-

import os
import sys
import subprocess
import run_semgrep as runner


def is_webapp(repo):
    return True if repo == "webapp" else False


def slack_repo(repo, git_repo, repo_path, repo_dir):
    if not os.path.isdir(repo_path):
        sys.exit(
            "[!!] webapp not found. Please run clone manually if running locally."
            f" Perhaps\n     with: GIT_LFS_SKIP_SMUDGE=1 git -C {repo_dir}"
            f" clone {git_repo} --depth 1"
        )
    print(f"[+] Updating repo: {repo}")
    command = f"git -C {repo_path} fetch --tags --force --progress -- {git_repo} +refs/heads/*:refs/remotes/origin1/*"
    process = runner.run_command(command)


def copy_repo_dir(repo_dir, git):
    if git == "ghe":
        repo = repo_dir.split("/")[-1]
        process = runner.run_command(f"cp -R ../{repo}/ {repo_dir}")


def commit_head(git):
    if git == "ghc":
        os.environ["CIBOT_COMMIT_HEAD"] = os.environ.get("GITHUB_SHA")
