import subprocess
import textwrap
import logging

from src.config import logger


def run_command(command: str, throw_error: bool = True):
    process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    process.stdout = process.stdout + process.stderr
    if (process.returncode != 0) and throw_error:
        error_msg = f"""
            The following command failed with return code {process.returncode}.
            Command: {process.args}
            Error: {process.stderr.decode("utf-8")}
            """
        logging.info(textwrap.dedent(error_msg))
        raise subprocess.CalledProcessError(returncode=process.returncode, cmd=process.args)
    return process


def create_ssh_url(repo_long):
    # slack-github.com/ebrowning/bapi2
    # git@slack-github.com:slack/bapi2.git
    loc = repo_long.find("/")
    git_ssh_url = f"git@{repo_long[:loc]}:{repo_long[loc+1:]}.git"
    return git_ssh_url


def sha1_verify(sha1: str):
    if len(sha1) == 40:
        return True
    return False


def check_for_origin(repo_long, repo_dir):
    git_dir = f"git -C {repo_dir}"
    git_ssh_origin = create_ssh_url(repo_long)
    process = run_command(f"{git_dir} remote -v")
    logging.info(f"remotes are: \n{process.stdout.decode('utf-8')}")
    process = run_command(f"{git_dir} remote -v | wc -l")
    if int(process.stdout.decode("utf-8")) < 2:
        process = run_command(f"{git_dir} remote add origin {git_ssh_origin}")
        logging.info(f"added origin: {git_ssh_origin}")
        process = process = run_command(f"{git_dir} remote -v")
        logging.info(f"remotes are now: \n{process.stdout.decode('utf-8')}")
