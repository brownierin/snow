#!/usr/bin/env python3

import pprint
import shlex
import subprocess

import os
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
from pathlib import Path


import src.webhooks as webhooks
import src.comparison as comparison
import aws.upload_to_s3 as s3
import src.checkpoint as checkpoint
import src.jenkins as jenkins
from src.exceptions import *
from src.config import *
from src.util import *
import src.verify
from src.git import *
from src.repos import *


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


def scan_repos():
    """
    Iterates over all repos in the enabled files and performs
    a Semgrep scan.
    """
    repos = get_repo_list()
    repolist_data = read_json(f"{RESULTS_DIR}repo_info.json")
    for repo_long in repos:
        language = find_repo_language(repo_long)
        repo = repo_long.split("/")[-1]
        git_sha = repolist_data[repo_long]["git_sha"]

        results, output_file = scan_repo(repo_long, language, git_sha)
        
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


def build_scan_command(config_lang, output_file, repo):
    cmd = ["semgrep", f"{CONFIG[config_lang]['config']}"]

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
    return " ".join(cmd)


def scan_repo(repo_long, language, git_sha):
    url, org, repo = repo_long.split("/")
    """
    Scans the repo with semgrep and adds metadata
    Returns the results and output file path
    """
    logging.info(f"Scanning repo: {repo}")
    config_lang = f"language-{language}"
    output_file = f"{language}-{repo}-{git_sha[:7]}.json"

    # create the commands to run in the container
    semgrep_command = build_scan_command(config_lang, output_file, repo)

    # with open("container.sh", 'w') as f:
    #     f.write("set +x")
    #     f.write(semgrep_command)
    #     # change file permissions since semgrep runs with user opam (higher priv)
    #     # this prevents some users (like the jenkins user) from opening result files
    #     f.write("chmod a+rw /src/results/")

    # container_cmd = f"docker run -td -v {SNOW_ROOT}:/src slack/semgrep /bin/sh container.sh"

    # logging.info(f"Docker command:\n {container_cmd}")
    logging.info(f"Semgrep command:\n {semgrep_command}")
    logging.info(f"Running Semgrep")

    # Using Popen to avoid buffer errors with Docker child processes
    with subprocess.Popen(shlex.split(semgrep_command), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1) as process:
        logging.info(f'{process.stdout.read().decode("ascii")}\n')

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


def run_semgrep_pr(repo_long):  
    url, org, repo = repo_long.split("/")
    repo_language = find_repo_language(repo_long)
    clean_workspace() if url == ghe_url else logging.info("Skipping cleanup")
    repo_info = read_json(f"{RESULTS_DIR}repo_info.json")
    master_sha = repo_info["master_sha"]
    branch_sha = repo_info["branch_sha"]

    prefix = f"{RESULTS_DIR}{repo_language}-{repo}-"
    master_out = f"{prefix}{master_sha[:7]}.json"
    branch_out = f"{prefix}{branch_sha[:7]}.json"
    comparison_out = f"{prefix}{master_sha[:7]}-{branch_sha[:7]}.json"
    fp_file = f"{SNOW_ROOT}/languages/{repo_language}/false_positives/{repo}_false_positives.json"
    fprm_out = f"{prefix}{master_sha[:7]}-{branch_sha[:7]}-fprm.json"

    if url == ghc_url:
        os.environ[artifact_dir_env] = RESULTS_DIR
        logging.info(f"Artifacts dir is: {os.environ[artifact_dir_env]}")

    mode = int("775", base=8)
    repo_dir = f"{REPOSITORIES_DIR}{repo}"
    os.makedirs(repo_dir, mode=mode, exist_ok=True)
    logging.info(f"Repository dir is at: {repo_dir}")

    git_dir = f"git -C {repo_dir}"

    logging.info(subprocess.run(f"{git_dir} worktree add branch", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.decode('utf-8'))
    logging.info(f"{git_dir} checkout -f {branch_sha}")
    checkout = run_command(f"{git_dir} checkout -f {branch_sha}")
    logging.info(checkout)
    logging.info(checkout.stdout.decode('utf-8'))
    logging.info(f"Scanning {repo} on branch commit {branch_sha[:7]}")
    scan_repo(repo_long, repo_language, branch_sha[:7])

    run_command(f"{git_dir} checkout -f {master_sha}")
    logging.info(f"Scanning {repo} on master commit {master_sha[:7]}")
    scan_repo(repo_long, repo_language, master_sha[:7])

    comparison.compare_to_last_run(master_out, branch_out, comparison_out)

    # False positives would rarely be removed because they would most
    # likely be caught in the above diff check
    comparison.remove_false_positives(comparison_out, fp_file, fprm_out)

    # shouldn't these be present at this point?
    add_hash_id(comparison_out, 4, 1, "hash_id")
    add_hash_id(fprm_out, 4, 1, "hash_id")

    content = create_results_blob(read_json(fprm_out))
    webhook_alerts(content)

    checkpoint.convert(fprm_out, comparison_out, fprm_out)
    if url == ghc_url:
        exit_code = checkpoint.upload_pr_scan(branch_sha, master_sha)
        set_exit_code(exit_code)

    if os.getenv("ENABLE_S3"):
        bucket = CONFIG["general"]["s3_bucket"]
        filenames = [fprm_out, comparison_out, master_out, branch_out]
        s3.upload_files(filenames, bucket)

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
        exit_code = src.verify.get_docker_image(args.mode)
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
