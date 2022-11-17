import subprocess
import shlex
import logging
import urllib
import os
import shutil
import json

import src.jenkins as jenkins
from config import *


def remove_scheme_from_url(url):
    parsed = urllib.parse.urlparse(url)
    if parsed.path.endswith(".git"):
        return parsed.netloc + parsed.path[:-4]
    else:
        return parsed.netloc + parsed.path


def run_command(command):
    return subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def run_long_command(command):
    command = shlex.split(command)
    logging.info(f"Shlex intepretation of command: {command}")
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1)

    while True:
        output = process.stdout.readline()
        if output:
            print(output.decode("utf-8"))
            # for line in output:
                # print(line.decode("utf-8").split("\n")[0])
        if process.poll() is not None:
            break
    return process


def set_ssh_key(url):
    if jenkins.get_ci_env() == "jenkins":
        if url == ghc_url:
            os.environ["GIT_SSH_COMMAND"] = "ssh -o IdentitiesOnly=yes -i $GHC_PRIVATE_KEY -o StrictHostKeyChecking=no"
            logging.info(f"Using {os.environ['GIT_SSH_COMMAND']}")
        elif url == ghe_url:
            os.environ["GIT_SSH_COMMAND"] = "ssh -o IdentitiesOnly=yes -i $GHE_PRIVATE_KEY -o StrictHostKeyChecking=no"
            logging.info(f"Using {os.environ['GIT_SSH_COMMAND']}")
        else:
            logging.info("Using default ssh key")

def rm_dir(repo_path):
    shutil.rmtree(repo_path)


def read_json(file):
    logging.info(f"Reading file {file}")
    with open(file, "r") as f:
        data = json.load(f)
    return data
