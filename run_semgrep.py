#!/usr/bin/env python3
# -*- coding: future_fstrings -*-

import pprint
import subprocess
import configparser
import os
import shutil
import json
import hashlib
import time
import checkpoint_out
import process_hash_ids as comparison
from pathlib import Path
import argparse
import sys
import datetime
import aws.upload_to_s3 as s3
import webhooks

# Get config file and read.
CONFIG = configparser.ConfigParser()
CONFIG.read('config.cfg')

# Global Variables
SNOW_ROOT = os.getenv('PWD')
if CONFIG['general']['run_local_semgrep'] != "False":
    SNOW_ROOT = CONFIG['general']['run_local_semgrep']
LANGUAGES_DIR = SNOW_ROOT + CONFIG['general']['languages_dir']
RESULTS_DIR = SNOW_ROOT + CONFIG['general']['results']
REPOSITORIES_DIR = SNOW_ROOT + CONFIG['general']['repositories']
FORKED_REPOS = {
    "orchestrator"  : "https://github.com/openark/orchestrator.git",
    "vitess"        : "https://github.com/vitessio/vitess.git",
    "unreleased"    : "https://github.com/electron/unreleased.git",
    "secor"         : "https://github.com/pinterest/secor.git",
    "trop"          : "https://github.com/electron/trop.git",
    "hive"          : "https://github.com/apache/hive.git",
    "kafka"         : "https://github.com/apache/kafka.git",
    "apache-ranger" : "https://github.com/apache/ranger.git",
    "fbthrift"      : "https://github.com/facebook/fbthrift.git"
}

def cleanup_workspace():
    print('[+] Begin workspace cleanup')
    mode = int('775', base=8)
    os.makedirs(RESULTS_DIR, mode=mode, exist_ok=True)
    clean_results_dir()
    os.makedirs(REPOSITORIES_DIR, mode=mode, exist_ok=True)
    print('[+] End workspace cleanup')


def clean_results_dir():
    """
    Removes all result files but the most recent 3
    """
    paths = []
    for path in Path(RESULTS_DIR).iterdir():
        paths.append(RESULTS_DIR + path.name)
    paths = sorted(paths, key=os.path.getmtime)
    repos = get_repo_list()
    for repo in repos:
        selected_paths = [x for x in paths if f"{repo}" in str(x)]
        if len(selected_paths) > 3:
            for file in selected_paths[:-3]:
                try:
                    os.remove(file)
                except FileNotFoundError:
                    print(f"[!!] Cannot clean result file. File not found! {file}")
                    continue


def get_repo_list():
    """
    Grabs all enabled repository names across all languages
    """
    repos = []
    for language in CONFIG.sections():
        if language.find('language-') != -1:
            filename = LANGUAGES_DIR + CONFIG[language]['language'] + '/enabled'
            with open(filename) as f:
                enabled = f.read().splitlines()
            repos = repos + [repo for repo in enabled]
    return repos


def get_docker_image(mode=None):
    version = CONFIG['general']['version']
    digest = CONFIG['general']['digest']

    download_semgrep(version)
    print("[+] Verifying Semgrep")
    digest_check_scan = check_digest(digest, version)

    if mode == "version":
        download_semgrep("latest")
        digest_check_update = check_digest(digest, "latest")
        if digest_check_update == -1:
            print("[!!] A new version of semgrep is available.")
            return 1
        else: 
            print("[+] Semgrep is up to date.")
            return 0
    else:
        if digest_check_scan != -1:
            raise Exception("[!!] Digest mismatch!")
        print("[+] Semgrep downloaded and verified")


def download_semgrep(version):
    print(f"[+] Downloading Semgrep {version}")
    run_command(f"docker pull returntocorp/semgrep:{version}")


def check_digest(digest, version):
    command = "docker inspect --format='{{.RepoDigests}}' returntocorp/semgrep:"+version
    process = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE)
    return digest.find((process.stdout).decode("utf-8"))


def run_command(command):
    return subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def git_ops(repo):
    repo_path = f"{REPOSITORIES_DIR}{repo}"
    git_repo = f"git@slack-github.com:slack/{repo}.git"
    if repo == "webapp":
        if not os.path.isdir(f"{repo_path}"):
            sys.exit("[!!] webapp not found. Please run clone manually if running locally. Perhaps\n"
                    f"     with: GIT_LFS_SKIP_SMUDGE=1 git -C {REPOSITORIES_DIR} clone {git_repo} --depth 1")
        print("[+] Updating webapp")
        command = (
                    f"git -C {REPOSITORIES_DIR}webapp "
                    f"fetch --tags --force --progress "
                    f"-- {git_repo} +refs/heads/*:refs/remotes/origin1/*"
                    )
        process = run_command(command)
    else:
        if os.path.isdir(f"{repo_path}"):
            print(f"[+] Updating repo: {repo}")
            pull = run_command(f"git -C {repo_path} pull")
        else:
            clone_command = f"git -C {REPOSITORIES_DIR} clone {git_repo}"
            clone = run_command(clone_command)
            # If we fail to download from Enterprise, try tinyspeck
            if clone.returncode == 128:
                git_repo = f"https://github.com/tinyspeck/{repo}.git"
                clone_command = f"git -C {REPOSITORIES_DIR} clone {git_repo}"
                clone = run_command(clone_command)
            print(clone.stdout.decode("utf-8"))


def git_forked_repos(repo, language, git_sha, git_repo_url):
    repo_path = f"{REPOSITORIES_DIR}{repo}"
    repo_language = language.replace("language-", "")

    # Setup the upstream repo as a remote
    forked_repo = FORKED_REPOS[repo]
    print(f"[+] Repository is forked from {forked_repo}.")

    # fetch the upstream repo
    command = (
                f"git -C {repo_path} remote | grep -q '^forked$' || "
                f"git -C {repo_path} remote add forked {forked_repo}"
            )
    run_command(command)
    run_command(f"git -C {repo_path} fetch forked")

    # Get the remote "master" branch name (not always "master")
    symref_process = run_command(f"git -C  {repo_path} remote show forked | sed -n '/HEAD branch/s/.*: //p'")
    remote_master_name = symref_process.stdout.decode("utf-8")

    # Identify the commit id it was forked from
    merge_base_process = run_command(f"git -C {repo_path} merge-base {git_sha} forked/{remote_master_name}")
    forked_commit_id = merge_base_process.stdout.decode("utf-8").strip()
    print(f"[+] Using the commit id {forked_commit_id} as the commit the repo is forked from.")

    # In this special case, we haven't pushed any custom code into the forked repo as the
    # HEAD of the slack repo exists in the repo we forked it from.
    #
    # Note: startswith is used in case the git_sha is a shortened commit hash.
    if forked_commit_id.startswith(git_sha):
        print(f"[+] We have detected that this repository doesn't contain any custom commits. Returning no findings because of this.")
        for suffix in ["", "-fprm"]:
            output = f"{RESULTS_DIR}{repo_language}-{repo}-{forked_commit_id[:7]}{suffix}.json"
            # This will remove all the entry of the results, but keep the metadata about the scan.
            # While this is sort-of weird code, it will ensure the output is consistent with other scan results.
            if os.path.exists(output):
                comparison.compare_to_last_run(output, output, output)
        return

    # Scan the repo for that commit ID
    scan_repo(repo, CONFIG[language]['language'], language, git_repo_url, forked_commit_id)

    # Compare the results and override the original result with the difference
    for suffix in ["", "-fprm"]:
        old_output = f"{RESULTS_DIR}{repo_language}-{repo}-{forked_commit_id[:7]}{suffix}.json"
        new_output = f"{RESULTS_DIR}{repo_language}-{repo}-{git_sha[:7]}{suffix}.json"

        if os.path.exists(old_output):
            comparison.compare_to_last_run(old_output, new_output, new_output)
            os.remove(old_output) # Cleanup

def download_repos():
    for language in CONFIG.sections():
        git_repo_url = "https://slack-github.com/"
        if language.find('language-') != -1:
            print(f"[!!] Downloading {language} repos")
            filename = LANGUAGES_DIR + CONFIG[language]['language'] + '/enabled'
            with open(filename) as f:
                content = f.read().splitlines()
            for repo in content:
                """ Download all the repos """
                git_ops(repo)

                """ Scan repos """
                get_sha_process = run_command(f"git -C {REPOSITORIES_DIR}{repo} rev-parse HEAD")
                git_sha = get_sha_process.stdout.decode("utf-8").rstrip()
                scan_repo(repo, CONFIG[language]['language'], language, git_repo_url, git_sha)

                # Special repos are repos that are forked from open-source library or project.
                # For those repos the results that we must consider for the scan are the diff 
                # between our current version and the original version it's forked from.
                if repo in FORKED_REPOS:
                    git_forked_repos(repo, language, git_sha, git_repo_url)


def scan_repo(repo, language, configlanguage, git_repo_url, git_sha):
    git_sha = git_sha.rstrip()
    print('[+] Scanning repo: ' + repo)
    output_file = f"{language}-{repo}-{git_sha[:7]}.json"
    semgrep_command = (
        f"docker run --user \"$(id -u):$(id -g)\" --rm "
        f"-v {SNOW_ROOT}:/src returntocorp/semgrep:{CONFIG['general']['version']} "
        f"{CONFIG[configlanguage]['config']} "
        f"{CONFIG[configlanguage]['exclude']} "
        "--json --dangerously-allow-arbitrary-code-execution-from-rules "
        f"-o /src{CONFIG['general']['results']}{output_file} "
        f"{CONFIG['general']['repositories'][1:]}{repo}"
    )
    print(f"[+] Docker scan command:\n {semgrep_command}")
    print("[+] Semgrep scan results")
    process = subprocess.run(semgrep_command, shell=True, stdout=subprocess.PIPE)
    # Results here should be sent to a new function for us to work with!
    print(process.stdout.decode("utf-8"))
    # We want to capture where these results came from. GitHub, and Branch in the file
    print("[+] Opening " + SNOW_ROOT + CONFIG['general']['results'] + output_file)
    # Read The Json Data
    with open(SNOW_ROOT + CONFIG['general']['results'] + output_file, ) as file:
        git_repo_branch = git_sha
        data = json.load(file)
        data.update({"metadata": {
            "GitHubRepo": git_repo_url,
            "branch": git_repo_branch,
            "repoName": repo,
            "language" : language,
            "timestamp" : datetime.datetime.now(tz=datetime.timezone.utc).isoformat()
        }})
    # Write to the same file
    with open(SNOW_ROOT + CONFIG['general']['results'] + output_file, 'w') as file:
        json.dump(data, file, sort_keys=True, indent=4)

    # fprm stands for false positives removed
    fp_diff_outfile = f"{language}-{repo}-{git_sha[:7]}-fprm.json"
    fp_file = f"{SNOW_ROOT}/languages/{language}/false_positives/{repo}_false_positives.json"

    # Add hash identifier to the json result
    # and remove false positives from the output file
    if os.path.exists(RESULTS_DIR+output_file):
        add_hash_id(RESULTS_DIR+output_file, 2, 1, "old_hash_id")
        add_hash_id(RESULTS_DIR+output_file, 4, 1, "hash_id")
        comparison.remove_false_positives(
                                            RESULTS_DIR+output_file,
                                            fp_file,
                                            RESULTS_DIR+fp_diff_outfile
                                        )

    git_branch_cmd = f"git -C {REPOSITORIES_DIR}/{repo} branch --show-current"
    process = subprocess.run(git_branch_cmd, shell=True, stdout=subprocess.PIPE)
    branch = process.stdout.decode('utf-8').rstrip()
    print(f"[+] Current branch: {branch}")

    if branch == "master":
        # sorts files by most recent
        paths = []
        for path in Path(RESULTS_DIR).iterdir():
            paths.append(RESULTS_DIR + path.name)
        paths = sorted(paths, key=os.path.getmtime)
        selected_paths = [x for x in paths if f"{language}-{repo}" in str(x)]
        comparison_result = f"{RESULTS_DIR}{fp_diff_outfile.split('-fprm')[0]}-comparison.json"
        print(f"[+] Comparison result is stored at: {comparison_result}")

        # get the second most recent result with fprm in it
        if len(selected_paths) > 2:
            for file in selected_paths[-5:-2]:
                if "fprm" in str(file):
                    old = file
                    print(f"[+] Old file is: {old}")
                    print(f"[+] Comparing {old} and {fp_diff_outfile}")
                    comparison.compare_to_last_run(old, RESULTS_DIR+fp_diff_outfile, comparison_result)
        else:
            print("[!!] Not enough runs for comparison")
        

# Grab source codes. Also include one line above and one line below the issue location
def read_line(issue_file, line, start_line, end_line):
    with open(issue_file) as f:
        content = f.readlines()
        # check lines
        start = line - start_line if line - start_line > 0 else 0
        end = line + end_line if len(content) >= line + end_line else len(content)
        data = content[start:end]
    return "".join(data).replace("\n", "|")


# Function to add hash field to the semgrep json output as a unique id
# The hash is sha 256 value of : check_id + path + 3 line of codes
# NOTE: We don't hash the line number. Code addition could change the line number
def add_hash_id(jsonFile, start_line, end_line, name):
    # Open json file
    f = open(jsonFile, "r")
    data = json.load(f)
    f.close()

    for issue in data["results"]:
        # Check issue metadata
        if (issue["path"] is None) or (issue["start"]["line"] is None):
            continue

        file_path = issue["path"]
        line = issue["start"]["line"]
        base_code = read_line(file_path, line, start_line, end_line)

        # Check line from out exist in the base_code
        if issue["extra"]["lines"] in base_code:
            base_hash = issue["check_id"] + "|" + file_path + "|" + base_code
        else:
            base_hash = (
                issue["check_id"] + "|" + file_path + "|" + issue["extra"]["lines"]
            )

        # Hash the base
        res = bytes(base_hash, "utf-8")
        hash_digest = hashlib.sha256(res).hexdigest()

        # Update the json blob
        issue[name] = hash_digest

    ## Save our changes to JSON file
    jsonFile = open(jsonFile, "w+")
    jsonFile.write(json.dumps(data))
    jsonFile.close()

# Alert Channel iterates through the /results directory. Reads the JSON files, and outputs the alerts to SLACK per CONFIG file.
# Alerts utilize the 'slack' command on servers, which allows messages to be sent. Careful with backticks.
# Alerts will not fire unless on a server 'slack'. Command is different on local env.
def alert_channel():
    current_jenkins_job = os.environ['JOB_NAME']
    # Sending the alerts to #alerts-snow channel only when the jenkins job is production, and not test/others. 
    if current_jenkins_job.lower() == CONFIG['general']['jenkins_prod_job'].lower():
        semgrep_output_files = os.listdir(RESULTS_DIR)
        semgrep_errors = False
        alert_json, error_json = {}, {}
        high, normal, total_vulns = 0, 0, 0
        #Get the high priority config

        high_priority_rules_check_id = CONFIG['high-priority']['high_priority_rules_check_id'].split('\n')
        high_priority_rules_message = CONFIG['high-priority']['high_priority_rules_message'].split('\n')

        # Iterate through the /results file
        for semgrep_output_file in semgrep_output_files:
            print("Reading JSON Output File " + semgrep_output_file)
            # Parse the json file and collect any results present
            with open(RESULTS_DIR + semgrep_output_file) as file:
                data = json.load(file)
                results = data["results"]
                errors = data["errors"]
                repo_name = data["metadata"]["repoName"]
                alert_json.update({repo_name: {"normal": [], "high": []}})
                github_url = data["metadata"]["GitHubRepo"]
                if github_url == "https://slack-github.com/":
                    github_url = github_url+"slack/"
                elif github_url == "https://github.com/":
                    github_url = github_url + "tinyspeck/"
                github_branch = data["metadata"]["branch"]
                # Check if there are results or errors.
                if type(results) is type({}):
                    for result in results:
                        check_id = result["check_id"]
                        # path always gives us /repositories/<repo>/dir/filename.py
                        # We do not want /repositories/ or <repo> as this is not valid for a GitHub url
                        code_path = result["path"].split('/', 2)[2:][0]
                        line_start = result["start"]["line"]
                        message = result["extra"]["message"]
                        # Because a single line JavaScript file exists we truncate...
                        code_lines = result["extra"]["lines"][:300]
                        code_url = github_url + repo_name + "/blob/" + github_branch + "/" + code_path + "#L" + str(line_start)
                        priority = "normal"
                        result_builder = "*Security Vulnerability Detected in "+repo_name+"*\n:exclamation:*Rule ID:* " + check_id + "\n:speech_balloon: *Message:* " + message + "\n:link:*Link*: "+code_url+"\n:coding_horror: *Code:*\n\`\`\`" + code_lines + "\`\`\`"
                        total_vulns = total_vulns+1
                        # Check if rule should be treated as a high priority alert.
                        if check_id in high_priority_rules_check_id:
                            high = high+1
                            priority = "high"
                        else:
                            for high_priority_string in high_priority_rules_message:
                                if high_priority_string in message:
                                    high = high+1
                                    priority = "high"
                        alert_json[repo_name][priority].append(result_builder)
                # If any errors, mark them. This is where we would add additional logic to output errors into a errors_builder.
                # Currently making errors pretty are out scope.
                if errors:
                    semgrep_errors = True
                    error_json.update({repo_name: errors})
        normal = total_vulns - high
        #########################################################################
        # !!!!!!Subprocess Slack Alerts, Will Only Work On SLACK Servers!!!!!!!!!
        #########################################################################

        # Semgrep Daily Run Banner + vulnerability count of total, high, normal.
        subprocess.run("echo \":snowflake:*Daily :block-s: :block-e: :block-m: :block-g: :block-r: :block-e: :block-p: Scan Report*:snowflake: \n :blob-throw-snow-left:*Rules Triggered*:blob-throw-snow-right:\n---High:"+str(high)+"\n---Normal:"+str(normal)+" \" | slack --channel="+CONFIG['general']['alertchannel']+" --cat --user=SNOW ",shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if total_vulns > 0:
            #Fire High Banner
            subprocess.run("echo \":fire: :fire: :fire: :fire: :fire: :fire:\n:fire::block-h: :block-i: :block-g: :block-h:  :fire:\n:fire: :fire: :fire: :fire: :fire: :fire:\" | slack --channel="+CONFIG['general']['alertchannel']+" --cat --user=SNOW ", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            for repo in alert_json:
                for vuln in alert_json[repo]['high']:
                    subprocess.run("echo \"" + vuln + "\" | slack --channel="+CONFIG['general']['alertchannel']+" --cat --user=SNOW ", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                    time.sleep(1)

            #Snowflake Normal Banner
            subprocess.run("echo \":snowflake::snowflake::snowflake::snowflake::snowflake::snowflake::snowflake::snowflake::snowflake:\n:snowflake: :block-n: :block-o: :block-r: :block-m: :block-a: :block-l: :snowflake:\n:snowflake::snowflake::snowflake::snowflake::snowflake::snowflake::snowflake::snowflake::snowflake: \" | slack --channel="+CONFIG['general']['alertchannel']+" --cat --user=SNOW ",shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            for repo in alert_json:
                for vuln in alert_json[repo]['normal']:
                    subprocess.run("echo \"" + vuln + "\" | slack --channel="+CONFIG['general']['alertchannel']+" --cat --user=SNOW ", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                    time.sleep(1)

        elif not error_json:
            # ALL HAIL THE GLORIOUS NO VULNS BANNER
            text = """:black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square:\n:black_square::sun-turtle::black_square::black_square::black_square::sun-turtle::black_square::black_square::sun-turtle::sun-turtle::black_square::black_square::black_square::black_square::sun-turtle::black_square::black_square::black_square::sun-turtle::black_square::sun-turtle::black_square::black_square::black_square::sun-turtle::black_square::sun-turtle::black_square::black_square::black_square::sun-turtle::black_square::black_square::black_square::sun-turtle::black_square::black_square::sun-turtle::sun-turtle::sun-turtle::black_square:\n:black_square::sun-turtle::sun-turtle::black_square::black_square::sun-turtle::black_square::sun-turtle::black_square::black_square::sun-turtle::black_square::black_square::black_square::sun-turtle::black_square::black_square::black_square::sun-turtle::black_square::sun-turtle::black_square::black_square::black_square::sun-turtle::black_square::sun-turtle::black_square::black_square::black_square::sun-turtle::sun-turtle::black_square::black_square::sun-turtle::black_square::sun-turtle::black_square::black_square::black_square::black_square:\n:black_square::sun-turtle::black_square::sun-turtle::black_square::sun-turtle::black_square::sun-turtle::black_square::black_square::sun-turtle::black_square::black_square::black_square::sun-turtle::black_square::black_square::black_square::sun-turtle::black_square::sun-turtle::black_square::black_square::black_square::sun-turtle::black_square::sun-turtle::black_square::black_square::black_square::sun-turtle::black_square::sun-turtle::black_square::sun-turtle::black_square::black_square::sun-turtle::sun-turtle::black_square::black_square:\n:black_square::sun-turtle::black_square::black_square::sun-turtle::sun-turtle::black_square::sun-turtle::black_square::black_square::sun-turtle::black_square::black_square::black_square::black_square::sun-turtle::black_square::sun-turtle::black_square::black_square::sun-turtle::black_square::black_square::black_square::sun-turtle::black_square::sun-turtle::black_square::black_square::black_square::sun-turtle::black_square::black_square::sun-turtle::sun-turtle::black_square::black_square::black_square::black_square::sun-turtle::black_square:\n:black_square::sun-turtle::black_square::black_square::black_square::sun-turtle::black_square::black_square::sun-turtle::sun-turtle::black_square::black_square::black_square::black_square::black_square::black_square::sun-turtle::black_square::black_square::black_square::black_square::sun-turtle::sun-turtle::sun-turtle::black_square::black_square::sun-turtle::sun-turtle::sun-turtle::black_square::sun-turtle::black_square::black_square::black_square::sun-turtle::black_square::sun-turtle::sun-turtle::sun-turtle::black_square::black_square:\n:black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square:"""
            subprocess.run("echo \"" + text + "\" | slack --channel="+CONFIG['general']['alertchannel']+" --cat --user=SNOW ", shell=True,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if semgrep_errors:
            # Right now I am purposely not outputting errors. There are a lot and its noise. To Do: Make a pretty output once cleaned.
            subprocess.run("echo \":test-error: There were errors this run. Check Jenkins https://jenkins.tinyspeck.com/job/security-semgrep-prodsec \" | slack --channel="+CONFIG['general']['alertchannel']+" --cat --user=SNOW ",
                shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    else:
        # This is not a production jenkins job. So no need to send alerts.
        pass


def run_semgrep_daily():
    # Delete all directories that would have old repos, or results from the last run as the build boxes may persist from previous runs.
    cleanup_workspace()
    # Get Semgrep Docker image, check against a known good hash
    get_docker_image()
    # Download the repos in the language enabled list and run
    download_repos()
    # Output Alerts to channel
    alert_channel()


def webhook_alerts(data):
    try:
        webhooks.send_webhook(data)
    except Exception as e:
        print(f"[-] Webhook failed to send: error is {e}")


def run_semgrep_pr(repo, git):
    # Delete all directories that would have old repos, or results from the last run as the build boxes may persist from previous runs.
    cleanup_workspace()
    mode = int('775', base=8)
    os.makedirs(REPOSITORIES_DIR + repo, mode=mode, exist_ok=True)
    # Grab the PR code, move it to the repository with it's own directory
    # We do this as it mimics the same environment configuration as the daily scan so we can re-use the code.
    # Move everything into 'SNOW/repositories/'. run_semgrep.py scans by looking for the repo name in the repositories/ directory.
    if git == 'ghe':
        subprocess.run("mv ../* ../.* " +REPOSITORIES_DIR + repo, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    get_docker_image()

    # Every repo in SNOW is tied to a language in the enabled file. The repo name has to be exactly the same as
    # what is shown on GitHub (rains, agenda, missions, etc). We will loop through the enabled files until we find the
    # associated language to the repo.
    repo_language = ""
    for language in os.listdir("languages"):
        with open("languages/" + language + "/enabled") as file:
            for line in file:
                line = line.rstrip()
                if line == repo:
                    repo_language = language
                    # Right now this script only supports one language at a time, but we can add more here in the future.
                    print(repo + " is of language " + language)
            file.close()
    if repo_language == "":
        raise Exception(f"No language found in snow for repo {repo} check with #triage-prodsec!")
    config_language = "language-" + repo_language

    # We really only support ghe right now, as tinyspeck doesn't really hook up with Checkpoint at this time.
    if git == "ghe":
        git_repo_url = "https://slack-github.com/"
    elif git == "ts":
        git_repo_url = "https://github.com/tinyspeck"
    else:
        raise Exception("No supported git url supplied.")

    if git == 'ts':
        os.environ['CIBOT_COMMIT_HEAD'] = os.environ.get('GITHUB_SHA')
        
    # As HEAD is on the current branch, it will retrieve the branch sha.
    git_sha_branch = os.environ.get('CIBOT_COMMIT_HEAD')
    git_sha_branch_short = git_sha_branch[:7]
    # Make sure you are on the branch to scan by switching to it.
    process = subprocess.run("git -C " + REPOSITORIES_DIR + repo + " checkout -f " + git_sha_branch, shell=True, check=True,stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print("Branch Checkout: " + process.stdout.decode("utf-8"))
    scan_repo(repo, repo_language, config_language, git_repo_url, git_sha_branch_short)
    print(os.environ.get('CIBOT_COMMIT_HEAD') + " sha branch")

    if git == 'ts':
        master_ref = open('.git/refs/heads/master', 'r')
        os.environ['CIBOT_COMMIT_MASTER'] = master_ref.read()
        os.environ['CIBOT_ARTIFACT_DIR'] = RESULTS_DIR

    git_sha_master = os.environ.get('CIBOT_COMMIT_MASTER')
    git_sha_master_short = git_sha_master[:7]
    print(f"{git_sha_master} sha master")

    if git_sha_branch == git_sha_master:
        print("[-] Master and HEAD are equal. Need to compare against two different SHAs! We won't scan.")
        sys.exit(0)

    # Switch repo to master, so we scan that.
    process = subprocess.run("git -C " + REPOSITORIES_DIR + repo + " checkout -f "+ git_sha_master, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print("Master Checkout: " + process.stdout.decode("utf-8"))
    scan_repo(repo, repo_language, config_language, git_repo_url, git_sha_master_short)

    # Pass in the branch and master to compare for new vulnerabilities. Output file in format language-repo-sha_master-sha_branch.json
    # IE: golang-rains-6466c2e6e900cdd9e8a501a695a3fc1025402d9a-2e29dd81fe30efca60694aa999f5b444fd5b829c.json

    old_output = f"{RESULTS_DIR}{repo_language}-{repo}-{git_sha_master_short}.json"
    new_output = f"{RESULTS_DIR}{repo_language}-{repo}-{git_sha_branch_short}.json"
    output_filename = f"{RESULTS_DIR}{repo_language}-{repo}-{git_sha_master_short}-{git_sha_branch_short}.json"
    comparison.compare_to_last_run(old_output, new_output, output_filename)
    
    # If there any vulnerabilities detected, remove the false positives.
    # Note: False positives would rarely be removed because it would most likely be caught in the above diff check
    # Save as a new filename appending -parsed.json to the end.
    # IE: golang-rains-6466c2e6e900cdd9e8a501a695a3fc1025402d9a-2e29dd81fe30efca60694aa999f5b444fd5b829c-parsed.json
    json_filename = f"{RESULTS_DIR}{repo_language}-{repo}-{git_sha_master_short}-{git_sha_branch_short}.json"
    parsed_filename = f"{RESULTS_DIR}{repo_language}-{repo}-{git_sha_master_short}-{git_sha_branch_short}-parsed.json"
    fp_file = f"{SNOW_ROOT}/languages/{repo_language}/false_positives/{repo}_false_positives.json"
    comparison.remove_false_positives(json_filename, fp_file, parsed_filename)

    process = subprocess.run("git -C " + REPOSITORIES_DIR + repo + " checkout -f " + git_sha_branch, shell=True, check=True,stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print("Branch Checkout: " + process.stdout.decode("utf-8"))
    add_hash_id(json_filename, 4, 1, "hash_id")
    add_hash_id(parsed_filename, 4, 1, "hash_id")
    add_hash_id(json_filename, 2, 1, "old_hash_id")
    add_hash_id(parsed_filename, 2, 1, "old_hash_id")

    with open(parsed_filename) as fileParsed:
        data = json.load(fileParsed)
        # No vulnerabilities would be checking for an empty array.

    checkpoint_out.convert(parsed_filename, json_filename, parsed_filename)

    if git == 'ts':
        bucket = CONFIG['general']['s3_bucket']
        filenames = [
            parsed_filename, 
            json_filename, 
            old_output, 
            new_output, 
            output_filename
        ]
        s3.upload_files(parsed_filename, bucket)

    if not data['results']:
        content = "No new vulnerabilities detected!"
    else: 
        content = f"""
        =======================================================
        =============New vulnerabilities Detected.=============
        =======================================================
        Please review the following output. Reach out to #triage-prodsec with questions.
        {data['results']}
        """

    print(content)

    if git == "ts":
        webhook_alerts(content)

    if data['results'] exit(0) else exit(1)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Runs Semgrep, either in daily scan or pull request mode."
    )
    parser.add_argument(
        "-m",
        "--mode",
        help="the mode you wish to run semgrep, daily or pr",
    )
    parser.add_argument(
        "-r",
        "--repo",
        help="the name of the git repo",
    )
    parser.add_argument(
        "-g",
        "--git",
        help="the github url you wish to scan, supported options ghe (github enterprise) and ts (tinyspeck)",
    )

    args = parser.parse_args()

    if args.mode == "daily":
        if args.repo or args.git:
            print("Daily mode does not support extra args. Ignoring them.")
        run_semgrep_daily()
    elif args.mode == "pr":
        run_semgrep_pr(args.repo, args.git)
    elif args.mode == "version":
        exit_code = get_docker_image(args.mode)
        print(exit_code)
        sys.exit(exit_code)
    else:
        parser.print_help()
