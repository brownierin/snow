#!/usr/bin/env python3
# -*- coding: future_fstrings -*-

import os
import sys
import subprocess
from run_semgrep import run_command


def slack_repo(repo, git_repo, repo_path, repo_dir):
    if repo == "webapp":
        if not os.path.isdir(repo_path):
            sys.exit(
                "[!!] webapp not found. Please run clone manually if running locally."
                f" Perhaps\n     with: GIT_LFS_SKIP_SMUDGE=1 git -C {repo_dir}"
                f" clone {git_repo} --depth 1"
            )
        print("[+] Updating webapp")
        command = (
            f"git -C {repo_path} "
            "fetch --tags --force --progress "
            f"-- {git_repo} +refs/heads/*:refs/remotes/origin1/*"
        )
        process = run_command(command)
    else:
        return


def move_repo_dir(repo_dir, git):
    if git == 'ghe':
        subprocess.run(
            "mv ../* ../.* " + repo_dir,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )


def commit_head(git):
    if git == 'ghc':
        os.environ['CIBOT_COMMIT_HEAD'] = os.environ.get('GITHUB_SHA')
