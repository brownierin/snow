#!/usr/bin/env python3

import pprint
import shlex
import subprocess
import configparser
import os
import shutil
import json
import hashlib
import time
import argparse
import sys
import re
import glob
import datetime
import logging.config
import logging
import urllib
from pathlib import Path

import slack
import webhooks
import comparison
import aws.upload_to_s3 as s3
import checkpoint_out as checkpoint
import ci.jenkins as jenkins
from exceptions import GitMergeBaseError, FilePermissionsError

SNOW_ROOT = os.path.dirname(os.path.realpath(__file__))
env = os.getenv("env")
CONFIG = configparser.ConfigParser()
if env == "snow-test":
    CONFIG.read(f"{SNOW_ROOT}/config/test.cfg")
else:
    CONFIG.read(f"{SNOW_ROOT}/config/prod.cfg")


# Global Variables
global_exit_code = 0
if CONFIG["general"]["run_local_semgrep"] != "False":
    SNOW_ROOT = CONFIG["general"]["run_local_semgrep"]
LANGUAGES_DIR = SNOW_ROOT + CONFIG["general"]["languages_dir"]
RESULTS_DIR = SNOW_ROOT + CONFIG["general"]["results"]
REPOSITORIES_DIR = SNOW_ROOT + CONFIG["general"]["repositories"]
commit_head_env = CONFIG["general"]["commit_head"]
master_commit_env = CONFIG["general"]["master_commit"]
artifact_dir_env = CONFIG["general"]["artifact_dir"]
with open(f"{SNOW_ROOT}/{CONFIG['general']['forked_repos']}") as file:
    FORKED_REPOS = json.load(file)
print_text = CONFIG["general"]["print_text"]
high_alert_text = CONFIG["alerts"]["high_alert_text"]
banner = CONFIG["alerts"]["banner"]
normal_alert_text = CONFIG["alerts"]["normal_alert_text"]
no_vulns_text = CONFIG["alerts"]["no_vulns_text"]
errors_text = CONFIG["alerts"]["errors_text"]
ghe_url = CONFIG["general"]["ghe_url"]
ghc_url = "github.com"


def clean_workspace():
    """
    If results are persisted between runs, this method
    cleans up the results dir
    """
    if no_cleanup:
        logging.info("Skipping workspace cleanup!")
        return
    logging.info("Begin workspace cleanup")
    mode = int("775", base=8)
    os.makedirs(RESULTS_DIR, mode=mode, exist_ok=True)
    clean_results_dir()
    os.makedirs(REPOSITORIES_DIR, mode=mode, exist_ok=True)
    logging.info("End workspace cleanup")


def set_exit_code(code):
    global global_exit_code
    if code > 0:
        global_exit_code = code


def clean_results_dir():
    """
    Removes all result files but the most recent 3
    """
    paths = []
    for path in Path(RESULTS_DIR).iterdir():
        paths.append(RESULTS_DIR + path.name)
    paths = sorted(paths, key=os.path.getmtime)
    repos = get_repo_list()
    repos = trim_repo_list(repos)
    for repo in repos:
        selected_paths = [x for x in paths if f"{repo}" in str(x)]
        if len(selected_paths) > 3:
            for file in selected_paths[:-3]:
                try:
                    os.remove(file)
                except FileNotFoundError:
                    logging.warning(f"[!!] Cannot clean result file. File not found! {file}")
                    continue


def trim_repo_list(repos):
    return [repo.split("/")[-1] for repo in repos]


def get_repo_list():
    """
    Grabs all enabled repository names across all languages
    """
    repos = []
    enabled_filename = set_enabled_filename()
    for language in CONFIG.sections():
        if language.find("language-") != -1:
            filename = f"{LANGUAGES_DIR}{CONFIG[language]['language']}/{enabled_filename}"
            with open(filename) as f:
                enabled = f.read().splitlines()
            repos = repos + [remove_scheme_from_url(repo) for repo in enabled]
    return repos


def remove_scheme_from_url(url):
    parsed = urllib.parse.urlparse(url)
    if parsed.path.endswith(".git"):
        return parsed.netloc + parsed.path[:-4]
    else:
        return parsed.netloc + parsed.path


def get_docker_image(mode=None):
    """
    Downloads docker images and compares the digests
    If mode = version, checks if semgrep has an update available
    and returns 1 if so
    """
    version = CONFIG["general"]["version"]
    digest = CONFIG["general"]["digest"]

    download_semgrep(version)
    logging.info("Verifying Semgrep")
    digest_check_scan = check_digest(digest, version)

    if mode == "version":
        download_semgrep("latest")
        digest_check_update = check_digest(digest, "latest")
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
        logging.info("Building container")
        build_container()


def download_semgrep(version):
    logging.info(f"Downloading Semgrep {version}")
    run_command(f"docker pull returntocorp/semgrep:{version}")


def check_digest(digest, version):
    command = f"docker inspect --format='{{.RepoDigests}}' returntocorp/semgrep:{version}"
    process = run_command(command)
    return digest.find((process.stdout).decode("utf-8"))


def run_command(command):
    return subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def git_pull_repo(repo_path):
    """
    When "git pull" fails it's sometimes because there was a
    force push done at some point to the repo.
    In this case the pull fails because we have local commits
    that don't exists in the remote.
    We attempt to fix this problem by rebasing the local repo
    with the main branch of the remote.
    A pull can also fail if we're in a headless state. The
    checkout below fixes this.
    """
    symref_process = run_command(f"git -C {repo_path} remote show origin | sed -n '/HEAD branch/s/.*: //p'")
    default_branch = symref_process.stdout.decode("utf-8")
    try:
        pull(repo_path, default_branch) or reset(repo_path, default_branch) or force_redownload(repo_path)
    except Exception as e:
        raise e


def force_redownload(repo_path):
    repo = repo_path.split("/")[-1]
    try:
        rm_dir(repo_path)
        git_ops(repo)
    except Exception as e:
        logging.exception(e)
    else:
        return True


def rm_dir(repo_path):
    shutil.rmtree(repo_path)


def pull(repo_path, default_branch):
    try:
        run_command(f"git -C {repo_path} checkout {default_branch}")
        run_command(f"git -C {repo_path} pull")
    except Exception as e:
        logging.exception(e)
    else:
        return True


def reset(repo_path, default_branch):
    try:
        run_command(f"git -C {repo_path} reset --hard origin/{default_branch}")
        run_command(f"git -C {repo_path} pull")
    except Exception as e:
        logging.exception(e)
    else:
        return True


def git_ops(repo):
    url, org, repo = repo.split("/")
    set_ssh_key(url)
    repo_path = f"{REPOSITORIES_DIR}{repo}"
    git_repo = f"git@{url}:{org}/{repo}.git"

    if slack.is_webapp(repo):
        slack.slack_repo(repo, git_repo, repo_path, REPOSITORIES_DIR)
    elif os.path.isdir(f"{repo_path}"):
        logging.info(f"Updating repo: {repo}")
        git_pull_repo(repo_path)
    else:
        logging.info(f"Cloning {repo}")
        clone_command = f"git -C {REPOSITORIES_DIR} clone {git_repo}"
        clone = run_command(clone_command)

        # Git repositories that are pulled from github.com are marked as unsafe and as such
        # subsequent git command may fail with error saying that the repository is untrusted.
        # This small fixes ensures that all the commands work on those repositories. We only
        # need to do this once after the repository is cloned.
        if url == ghc_url:
            trust_this_repo_command = f"git config --global --add safe.directory {repo_path}"
            run_command(trust_this_repo_command)


def git_forked_repos(repo_long, language, git_sha):
    url, org, repo = repo_long.split("/")
    repo_path = f"{REPOSITORIES_DIR}{repo}"
    repo_language = language.replace("language-", "")

    # Setup the upstream repo as a remote
    forked_repo = FORKED_REPOS[repo]
    logging.info(f"Repository is forked from {forked_repo}.")

    # fetch the upstream repo
    command = f"git -C {repo_path} remote | grep -q '^forked$' || git -C {repo_path} remote add forked {forked_repo}"
    run_command(command)
    run_command(f"git -C {repo_path} fetch forked")

    # Get the remote "master" branch name (not always "master")
    cmd = f"git -C {repo_path} remote show forked | sed -n '/HEAD branch/s/.*: //p'"
    symref_process = run_command(cmd)
    remote_master_name = symref_process.stdout.decode("utf-8")

    # Identify the commit id it was forked from
    try:
        forked_commit_id = git_merge_base(repo_path, git_sha, remote_master_name)
    except GitMergeBaseError as e:
        message = f"Skipping scanning fork of {repo}. git merge_base failed. {e.message}"
        logging.error(message)
        webhooks.send(f"*Error*: {message}")
        return

    """
    In this special case, we haven't pushed any custom code into the forked 
    repo as the HEAD of the repo exists in the repo we forked it from.
    Note: startswith is used in case the git_sha is a shortened commit hash.
    """
    if forked_commit_id.startswith(git_sha):
        logging.info(
            "We have detected that this repository doesn't contain any custom commits. "
            "Returning no findings because of this."
        )
        for suffix in ["", "-fprm"]:
            output = f"{RESULTS_DIR}{repo_language}-{repo}-{forked_commit_id[:7]}{suffix}.json"
            # This will remove all the entries in the results but keeps the metadata about the scan.
            # While this is odd code, it will ensure the output is consistent with other scan results.
            if os.path.exists(output):
                comparison.compare_to_last_run(output, output, output)
        return

    scan_repo(repo_long, language, forked_commit_id)

    # Compare the results and overwrite the original result with the comparison result
    for suffix in ["", "-fprm"]:
        file_prefix = f"{RESULTS_DIR}{repo_language}-{repo}-"
        forked_output = f"{forked_commit_id[:7]}{suffix}.json"
        new_output = f"{file_prefix}{git_sha[:7]}{suffix}.json"

        if os.path.exists(forked_output):
            comparison.compare_to_last_run(forked_output, new_output, new_output)
            os.remove(forked_output)


def git_merge_base(repo_path, git_sha, remote_master_name):
    cmd = f"git -C {repo_path} merge-base {git_sha} forked/{remote_master_name}"
    try:
        merge_base_process = run_command(cmd)
        forked_commit_id = merge_base_process.stdout.decode("utf-8").strip()
    except subprocess.CalledProcessError:
        raise GitMergeBaseError
    else:
        logging.info(f"Using the commit id {forked_commit_id} as the commit the repo is forked from.")
        return forked_commit_id


def download_repos():
    """
    Download all repos listed in the enabled files
    """
    repos = get_repo_list()
    for repo in repos:
        git_ops(repo)


def scan_repos():
    """
    Iterates over all repos in the enabled files and performs
    a Semgrep scan.
    """
    repos = get_repo_list()
    for repo_long in repos:
        url, org, repo = repo_long.split("/")
        set_ssh_key(url)
        language = find_repo_language(repo_long)

        """
        Get the default branch name
        """
        cmd = "git remote show origin | grep 'HEAD branch' | sed 's/.*: //'"
        default_branch_name = run_command(cmd).stdout.decode("utf-8")
        logging.info(f"Default branch name: {default_branch_name.strip()}")
        get_sha_process = run_command(f"git -C {REPOSITORIES_DIR}{repo} rev-parse HEAD")
        git_sha = get_sha_process.stdout.decode("utf-8").rstrip()

        """
        Scan the repo and perform the comparison
        """
        results, output_file = scan_repo(repo_long, language, git_sha)
        """
        Required with the jump to semgrep version 0.120.0. The semgrep dockerfile now
        creates a non-root user different from the host's user, so we need to give the
        user outside of the container permissions to read the results folder
        """
        process_results(output_file, repo, language, git_sha[:7])

        """
        Special repos are repos that are forked from open-source libraries or projects.
        For those repos, the results that we must consider for the scan are the diff
        between our current version and the original version it's forked from.
        """
        if repo in FORKED_REPOS:
            git_forked_repos(repo_long, language, git_sha)


def add_metadata(repo_long, language, git_sha, output_file):
    """
    Adds metadata and finding hash_id to a scan result
    """
    url, org, repo = repo_long.split("/")
    output_file_path = f"{RESULTS_DIR}{output_file}"
    configlanguage = f"language-{language}"
    logging.info(f"Adding metadata to {output_file_path}")

    with open(output_file_path, "r") as file:
        """
        Update the metadata on the scan result
        """
        data = json.load(file)
        metadata = {
            "metadata": {
                "git_url": url,
                "git_org": org,
                "branch": git_sha,
                "repo_name": repo,
                "language": language,
                "timestamp": datetime.datetime.now(tz=datetime.timezone.utc).isoformat(),
            }
        }
        data.update(metadata)

    with open(output_file_path, "w") as file:
        json.dump(data, file, sort_keys=True, indent=4)

    if os.path.exists(output_file_path):
        add_hash_id(output_file_path, 4, 1, "hash_id")


def process_results(output_file, repo, language, sha):
    output_file_path = f"{RESULTS_DIR}{output_file}"
    """
    Note: "fprm" stands for false positives removed
    """
    fp_diff_outfile = f"{language}-{repo}-{sha}-fprm.json"
    fp_diff_file_path = RESULTS_DIR + fp_diff_outfile
    fp_file = f"{SNOW_ROOT}/languages/{language}/false_positives/{repo}_false_positives.json"

    if os.path.exists(output_file_path):
        comparison.remove_false_positives(output_file_path, fp_file, fp_diff_file_path)

    """
    Sort result files by most recent
    Get the second most recent result with fprm in it
    """
    selected_paths = list(glob.glob(f"{RESULTS_DIR}{language}-{repo}-*-fprm.json"))
    selected_paths = sorted(selected_paths, key=os.path.getmtime)
    selected_paths = regex_sha_match(selected_paths, repo, language)
    comparison_result = f"{fp_diff_file_path.split('-fprm')[0]}-comparison.json"
    logging.info(f"Comparison result is stored at: {comparison_result}")

    if len(selected_paths) >= 2:
        old = selected_paths[-2]
        logging.info(f"Old file is: {old}")
        logging.info(f"Comparing {old} and {fp_diff_outfile}")
        comparison.compare_to_last_run(old, fp_diff_file_path, comparison_result)
    else:
        logging.warning("[!!] Not enough runs for comparison")


def regex_sha_match(selected_paths, repo, language):
    # in the case where a repo has the same name as the prefix of another repo,
    # this ensures they won't be in the selected_paths.
    # e.g., for repos named hello and hello-again, hello won't have hello-again's
    # results in its selected_paths
    paths = []
    for f in selected_paths:
        sha = re.findall(r"([a-fA-F\d]{7})", f)[0]
        location = f.find(sha)
        expected_path = f"{language}-{repo}-{f[location:location+7]}"
        if expected_path in f:
            paths.append(f)
    return paths


def build_dockerfile():
    version = CONFIG["general"]["version"]
    dockerfile = f"FROM returntocorp/semgrep:{version}"
    with open("Dockerfile", "w") as f:
        f.write(dockerfile)


def build_container():
    build_dockerfile()
    run_command(f"docker build -t slack/semgrep .")


def build_scan_command(config_lang, output_file, repo, container):
    cmd = shlex.split(f"docker exec -it {container}")
    cmd = cmd + ["semgrep", f"{CONFIG[config_lang]['config']}"]

    for x in f"{CONFIG[config_lang]['exclude']}".split(" "):
        if x:
            cmd.append(x)

    remainder = [
        "--json",
        "--metrics",
        "off",
        f"-o",
        f"/src{CONFIG['general']['results']}{output_file}",
        f"{CONFIG['general']['repositories'][1:]}{repo}",
    ]
    for remains in remainder:
        cmd.append(remains)

    if slack.is_webapp(repo):
        for item in cmd:
            if "--config=/src/languages/hacklang" in item:
                new_item = "--config=/src/languages/hacklang/generics"
                cmd.remove(item)
                cmd.insert(-1, new_item)
        cmd.insert(-1, "--config=/src/frameworks/hacklang-webapp/")
    return cmd


def scan_repo(repo_long, language, git_sha):
    url, org, repo = repo_long.split("/")
    """
    Scans the repo with semgrep and adds metadata
    Returns the results and output file path
    """
    logging.info(f"Scanning repo: {repo}")
    config_lang = f"language-{language}"
    output_file = f"{language}-{repo}-{git_sha[:7]}.json"

    # create the docker container
    mount = f"{SNOW_ROOT}:/src"
    container = run_command(f"docker run -t -d -v {mount} slack/semgrep").stdout.decode("utf-8")

    semgrep_command = build_scan_command(config_lang, output_file, repo, container)

    logging.info(f"Docker scan command:\n {' '.join(semgrep_command)}")
    logging.info(f"Running Semgrep")

    # Not using run_command here because we want to ignore the exit code of semgrep.
    # Using Popen to avoid buffer errors with Docker child processes
    with subprocess.Popen(semgrep_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1) as process:
        logging.info(f'{process.stdout.read().decode("ascii")}\n')
    
    # change file permissions since semgrep runs with user opam (higher priv)
    run_command(f"docker exec --it {container} chmod a+rw results/")

    # stop container
    run_command(f"docker rm -f {container}")

    output_file_path = f"{RESULTS_DIR}{output_file}"
    with open(output_file_path) as f:
        findings = json.load(f)
        results = json.dumps(findings, indent=4)

    if url == ghe_url or print_text == "true":
        logging.info(f"Semgrep scan results:\n {results}")
    add_metadata(repo_long, language, git_sha, output_file)
    return results, output_file


def read_line(issue_file, line, start_line, end_line):
    """
    Grab source code. Include x lines above and x lines below
    the issue location
    """
    with open(issue_file) as f:
        content = f.readlines()
        start = line - start_line if line - start_line > 0 else 0
        end = line + end_line if len(content) >= line + end_line else len(content)
        data = content[start:end]
    return "".join(data).replace("\n", "|")


def add_hash_id(jsonFile, start_line, end_line, name):
    """
    Adds hash_id field to the semgrep json output as a unique id
    The hash is the sha256 value of : check_id + path + 3 line of codes
    NOTE: We don't hash the line number. Code addition could change the line number
    """
    logging.info(f"Adding hash_id to {jsonFile}")

    with open(jsonFile, "r") as file:
        data = json.load(file)

    for issue in data["results"]:
        # Check issue metadata
        if (issue["path"] is None) or (issue["start"]["line"] is None):
            continue

        file_path = issue["path"]
        line = issue["start"]["line"]
        base_code = read_line(file_path, line, start_line, end_line)

        # Check line from out exists in the base_code
        if issue["extra"]["lines"] in base_code:
            base_hash = issue["check_id"] + "|" + file_path + "|" + base_code
        else:
            base_hash = issue["check_id"] + "|" + file_path + "|" + issue["extra"]["lines"]

        res = bytes(base_hash, "utf-8")
        hash_digest = hashlib.sha256(res).hexdigest()
        issue[name] = hash_digest

    with open(jsonFile, "w+") as file:
        file.write(json.dumps(data))


def process_one_result(result, github_url, git_org, repo_name, github_branch):
    check_id = result["check_id"]
    line_start = result["start"]["line"]
    message = result["extra"]["message"]

    """
    path always gives us /repositories/<repo>/dir/filename.py
    We do not want /repositories/ or <repo> as this is not valid for a GitHub url
    """
    code_path = result["path"].split("/", 2)[2]

    # Because single line js files exists we truncate the length of the line
    code_lines = result["extra"]["lines"][:300]
    high_priority_rules_check_id = CONFIG["high-priority"]["high_priority_rules_check_id"].split("\n")
    high_priority_rules_message = CONFIG["high-priority"]["high_priority_rules_message"].split("\n")
    code_url = f"{github_url}/{git_org}/{repo_name}/tree/{github_branch}/{code_path}#L{str(line_start)}"
    priority = "normal"
    result_builder = f"""
        *Security Vulnerability Detected in {repo_name}*
        :exclamation: *Rule ID:* {check_id}
        :speech_balloon: *Message:* {message}
        :link:*Link*: [click me]({code_url})
        :coding_horror: *Code:*```{code_lines}```
    """

    if check_id in high_priority_rules_check_id:
        high = 1
        priority = "high"
    else:
        for high_priority_string in high_priority_rules_message:
            if high_priority_string in message:
                high = 1
                priority = "high"
    return result_builder, high, priority


def alert_channel():
    """
    This method iterates through the /results directory.
    It reads the JSON files and outputs alerts to Slack through a webhook.
    """
    semgrep_output_files = os.listdir(RESULTS_DIR)
    semgrep_errors = False
    alert_json, error_json = {}, {}
    high, normal, total_vulns = 0, 0, 0
    comparison_files = [x for x in semgrep_output_files if "-comparison" in str(x)]

    for semgrep_output_file in comparison_files:
        logging.info(f"Reading output file: {semgrep_output_file}")
        with open(RESULTS_DIR + semgrep_output_file) as file:
            data = json.load(file)
            results = data["results"]
            errors = data["errors"]
            repo_name = data["metadata"]["repo_name"]
            git_org = data["metadata"]["git_org"]
            alert_json.update({repo_name: {"normal": [], "high": []}})
            url = data["metadata"]["git_url"]
            github_branch = data["metadata"]["branch"]

            if results:
                total_vulns = len(results)
                for result in results:
                    processed, highs, priority = process_one_result(result, url, git_org, repo_name, github_branch)
                    alert_json[repo_name][priority].append(processed)
                    high += highs
            """
            If semgrep has errors, mark them. This is where we would add additional 
            logic to output errors into a errors_builder.
            Currently making errors pretty is out scope.
            """

            logging.info("total vulns " + str(total_vulns))
            logging.info("high vulns " + str(high))
            logging.info("normal vulns " + str(normal))
            if errors:
                semgrep_errors = True
                error_json.update({repo_name: errors})
    normal = total_vulns - high

    # Print the Semgrep daily run banner and vulnerability counts
    banner_and_count = f"""
        {banner}
        ---High: {str(high)}
        ---Normal: {str(normal)}
        """
    webhook_alerts(banner_and_count)
    if total_vulns > 0:
        if high > 0:
            webhook_alerts(high_alert_text)
            for repo in alert_json:
                for vuln in alert_json[repo]["high"]:
                    webhook_alerts(vuln)
                    time.sleep(1)

        if normal > 0:
            webhook_alerts(normal_alert_text)
            for repo in alert_json:
                for vuln in alert_json[repo]["normal"]:
                    webhook_alerts(vuln)
                    time.sleep(1)

    elif not error_json:
        # ALL HAIL THE GLORIOUS NO VULNS BANNER
        webhook_alerts(no_vulns_text)
    if semgrep_errors:
        # Right now we're purposely not outputting errors. It's noisy.
        # TODO: Make a pretty output once cleaned.
        webhook_alerts(errors_text)


def webhook_alerts(data):
    try:
        webhooks.send(data)
    except Exception as e:
        logging.exception(f"Webhook failed to send: error is {e}")


def set_enabled_filename():
    if env == "snow-test":
        return "enabled-test"
    else:
        return "enabled"


def find_repo_language(repo):
    """
    Every repo in SNOW is tied to a language in the enabled file.
    The repo name must be exactly the same as what is shown on GitHub.
    We will loop through the enabled files until we find the
    associated language to the repo.
    Note: Right now this script only supports one language per repo.
    """
    repo_language = ""
    for entry in CONFIG.sections():
        if entry.find("language-") != -1:
            enabled_filename = set_enabled_filename()
            language = CONFIG[entry]["language"]
            filename = f"{LANGUAGES_DIR}{language}/{enabled_filename}"
            with open(filename) as f:
                content = f.read().splitlines()
                for line in content:
                    if line == repo:
                        logging.info(f"{repo} is written in {language}")
                        repo_language = language
                        return repo_language
    logging.info(f"repo-lang is {repo_language}")
    if repo_language == "":
        raise Exception(f"[!!] No language found in snow for repo {repo}. Check in with #triage-prodsec!")


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


def run_semgrep_pr(repo_long):
    repo_long = remove_scheme_from_url(repo_long)
    url, org, repo = repo_long.split("/")
    clean_workspace() if url == ghe_url else logging.info("Skipping cleanup")

    mode = int("775", base=8)
    repo_dir = REPOSITORIES_DIR + repo
    os.makedirs(repo_dir, mode=mode, exist_ok=True)
    logging.info(f"Repository dir is at: {repo_dir}")

    get_docker_image()

    repo_language = find_repo_language(repo_long)
    slack.commit_head(url)

    # As HEAD is on the current branch, it will retrieve the branch sha.
    branch_sha = os.environ.get(commit_head_env)

    git_dir = f"git -C {repo_dir}"

    # Get the master commit id
    run_command(f"{git_dir} branch --list --remote origin/master")
    if os.environ.get(master_commit_env):
        master_sha = os.environ.get(master_commit_env)
    else:
        cmd = f"{git_dir} show -s --format='%H' origin/master"
        master_sha = subprocess.run(cmd, shell=True, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
        master_sha = master_sha.stdout.decode("utf-8").strip()

    # Make sure you are on the branch to scan by switching to it.
    process = run_command(f"{git_dir} checkout -f {branch_sha}")
    logging.info(f"Branch SHA: {branch_sha}")

    # Make sure we are scanning what the repo would look like after a merge
    # This prevents issues where a vulnerability is removed in master and the
    # scan wronly believes that it's introduced by the PR branch because the PR
    # branch is based on a commit that was before the vulnerability was removed.
    process = run_command(f"{git_dir} merge {master_sha}")
    scan_repo(repo_long, repo_language, branch_sha[:7])

    logging.info(f"Master SHA: {master_sha}")
    if url == ghc_url:
        os.environ[artifact_dir_env] = RESULTS_DIR
        logging.info(f"Artifacts dir is: {os.environ[artifact_dir_env]}")

    if branch_sha == master_sha:
        logging.error("Master and HEAD are equal. Need to compare against two different SHAs! We won't scan.")
        sys.exit(0)

    cmd = f"{git_dir} checkout -f {master_sha}"
    process = run_command(cmd)
    logging.info(f"Master Checkout: {process.stdout.decode('utf-8')}")
    scan_repo(repo_long, repo_language, master_sha[:7])

    prefix = f"{RESULTS_DIR}{repo_language}-{repo}-"
    master_out = f"{prefix}{master_sha[:7]}.json"
    branch_out = f"{prefix}{branch_sha[:7]}.json"
    comparison_out = f"{prefix}{master_sha[:7]}-{branch_sha[:7]}.json"
    comparison.compare_to_last_run(master_out, branch_out, comparison_out)

    # If there any vulnerabilities detected, remove the false positives.
    # Note: False positives would rarely be removed because it would most
    # likely be caught in the above diff check
    # Save as a new filename appending -parsed.json to the end.
    # IE: golang-rains-6466c2e-2e29dd8-parsed.json
    json_filename = f"{prefix}{master_sha[:7]}-{branch_sha[:7]}.json"
    parsed_filename = f"{prefix}{master_sha[:7]}-{branch_sha[:7]}-parsed.json"
    fp_file = f"{SNOW_ROOT}/languages/{repo_language}/false_positives/{repo}_false_positives.json"

    comparison.remove_false_positives(json_filename, fp_file, parsed_filename)

    process = run_command(f"{git_dir} checkout -f {branch_sha}")
    logging.info("Branch Checkout: " + process.stdout.decode("utf-8"))
    add_hash_id(json_filename, 4, 1, "hash_id")
    add_hash_id(parsed_filename, 4, 1, "hash_id")

    with open(parsed_filename) as fileParsed:
        data = json.load(fileParsed)

    checkpoint.convert(parsed_filename, json_filename, parsed_filename)
    if url == ghc_url:
        exit_code = checkpoint.upload_pr_scan(branch_sha, master_sha)
        set_exit_code(exit_code)

    if os.getenv("ENABLE_S3"):
        bucket = CONFIG["general"]["s3_bucket"]
        filenames = [parsed_filename, json_filename, old_output, new_output, output_filename]
        s3.upload_files(filenames, bucket)

    content = create_results_blob(data)
    webhook_alerts(content)
    with open(f"{RESULTS_DIR}results_blob.txt", "w+") as file:
        file.write(content)

    set_exit_code(0) if not data["results"] else set_exit_code(1)
    if url == ghc_url:
        exit(0)


def create_results_blob(data):
    if not data["results"]:
        content = "No new vulnerabilities detected!"
    else:
        content = f"""
        New vulnerabilities detected
        ============================
        Please review the following output.
        Reach out to #triage-prodsec with questions.
        Found {str(len(data['results']))} findings
        """
        count = 1
        for result in data["results"]:
            content += f"### Finding #{count}"
            content += prettyprint(result)
            count += 1

    return content.replace("  ", "")


def prettyprint(result):
    content = f"""
        Rule name: {result['check_id']}
        Affected file: {result['path']}:{result['start']['line']}
        Code: `{result['extra']['lines']}`
        Fix: {result['extra']['message']}\n
    """
    return content


def run_semgrep_daily():
    # Delete all directories that would have old repos, or results from the last run as the build boxes may persist from previous runs.
    clean_workspace()
    # Get Semgrep Docker image, check against a known good hash
    get_docker_image()
    # Download the repos in the language enabled list and run
    download_repos()
    scan_repos()
    # Output alerts to Slack
    if jenkins.get_job_name().lower() == CONFIG["general"]["jenkins_prod_job"].lower():
        alert_channel()
    elif os.environ.get("GITHUB_ACTION"):
        alert_channel()
    # Upload the results to checkpoint
    if env != "snow-test":
        set_exit_code(checkpoint.upload_daily_scan_results_to_checkpoint())


if __name__ == "__main__":
    logging.config.fileConfig(fname=f"{SNOW_ROOT}/config/logging.ini")
    parser = argparse.ArgumentParser(description="Runs Semgrep, either in daily scan or pull request mode.")
    parser.add_argument("-m", "--mode", help="the mode you wish to run semgrep, daily or pr", required=True)
    parser.add_argument("-r", "--repo", help="the name of the git repo")
    parser.add_argument("--s3", help="upload to s3", action="store_true")
    parser.add_argument("--no-cleanup", help="skip cleanup", action="store_true")

    args = parser.parse_args()

    if args.s3:
        os.environ["ENABLE_S3"] = True

    global no_cleanup
    no_cleanup = True if args.no_cleanup else False

    if args.mode == "daily":
        if args.repo:
            logging.warning("Daily mode does not support repo args. Ignoring them.")
        run_semgrep_daily()
    elif args.mode == "pr":
        run_semgrep_pr(args.repo)
    elif args.mode == "version":
        exit_code = get_docker_image(args.mode)
        logging.info(exit_code)
        sys.exit(exit_code)
    else:
        parser.print_help()

    """
    Exit the program with the expected exit code.
    If a non-blocking error occured during the execution of this program,
    "global_exit_code" will be change to "1". Otherwise it will stay at "0".
    """
    sys.exit(global_exit_code)
