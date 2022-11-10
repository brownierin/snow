import logging
from textwrap import dedent

from src.config import *
from src.util import *


def get_docker_image(mode=None):
    """
    Downloads docker images and compares the digests
    If mode = version, checks if semgrep has an update available
    and returns 1 if so
    """

    download_semgrep(VERSION)
    logging.info("Verifying Semgrep")
    digest_check_scan = check_digest(DIGEST, VERSION)

    if mode == "version":
        download_semgrep("latest")
        digest_check_update = check_digest(DIGEST, "latest")
        if digest_check_update == -1:
            logging.info("[!!] A new version of semgrep is available.")
            return 1
        else:
            logging.info("Semgrep is up to date.")
            return 0
    else:
        if digest_check_scan != -1:
            raise Exception("[!!] Digest mismatch!")
        logging.info("Semgrep downloaded and verified")


def download_semgrep(version):
    logging.info(f"Downloading Semgrep {version}")
    run_command(f"docker pull returntocorp/semgrep:{version}")


def check_digest(digest, version):
    command = f"docker inspect --format='{{.RepoDigests}}' returntocorp/semgrep:{version}"
    process = run_command(command)
    return digest.find((process.stdout).decode("utf-8"))


def build_dockerfile():
    logging.info("Creating dockerfile")
    version = CONFIG["general"]["version"]
    dockerfile = f"""\
        FROM returntocorp/semgrep:{version}
        ENTRYPOINT []
        RUN python3 -m pip install poetry
        WORKDIR /src
        COPY pyproject.toml /src
        RUN poetry install
        ENV env=snow-test
    """
    with open("Dockerfile", "w") as f:
        f.write(dedent(dockerfile))


def build_container():
    logging.info("Building container")
    run_long_command(f"docker build -t slack/semgrep {SNOW_ROOT}")

