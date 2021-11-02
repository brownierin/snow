#!/usr/bin/env python3
# -*- coding: future_fstrings -*-

import json
import argparse
import os
import shutil
import configparser
import time
import glob
import subprocess
import chardet
import ci.jenkins as jenkins
import webhooks

env = os.getenv("env")
CONFIG = configparser.ConfigParser()
if env != "snow-test":
    CONFIG.read('config.cfg')
else:
    CONFIG.read('config-test.cfg')
CHECKPOINT_API_URL = CONFIG['general']['checkpoint_api_url']
CHECKPOINT_TOKEN_ENV = CONFIG['general']['checkpoint_token_env']
TSAUTH_TOKEN_ENV = CONFIG['general']['tsauth_token_env']
RESULTS_DIR = os.getenv('PWD') + CONFIG['general']['results']


def uberproxy_curl_installed():
    process = subprocess.Popen(["slack", "help"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    return "uberproxy-curl" in process.stdout.read().decode("utf-8")


def get_tsauth_auth_token():
    return os.getenv(TSAUTH_TOKEN_ENV)


def call_checkpoint_api(url, post_params, tsauth_auth_token=None):
    """
    For internal testing, we can use the local command "uberproxy-curl" for TSAuth.
    If no TSAuth token is configured, we assume that it's running from a
    local environment which has the uberproxy-curl command
    """
    headers = {"Content-Type": "application/json"}

    try:
        if tsauth_auth_token is None:
            raw_result = uberproxy_curl(
                url=CHECKPOINT_API_URL + url, method="POST", headers=headers, content=json.dumps(post_params)
            )

            result = json.loads(raw_result.decode(chardet.detect(raw_result)["encoding"]))
            return result
        else:
            # External authentication requires a TSAuth token.
            headers["Authorization"] = f"Bearer {tsauth_auth_token}"

            r = requests.post(url=CHECKPOINT_API_URL + url, headers=headers, json=post_params)

            return r.json()
    except Exception as e:
        """
        To simplify error handling, we return an object that indicates a failure.
        All the error logic can be handled by the callee of this function.
        """
        send_webhook(post_params)
        return {"ok": False, "error": str(e)}


def send_webhook(post_params):
    repo = post_params["test_run"]["repo"]
    master = post_params["test_run"]["commit_master"]
    branch = post_params["test_run"]["commit_head"]
    content = (
        f"Uploading to checkpoint failed!\nGo check {repo} for branch commit {branch}\nversus master commit {master}"
    )
    webhooks.send(content)


def uberproxy_curl(url, method, headers={}, content=None):
    # Use "uberproxy-curl" to reach checkpoint API
    cmdline = ["slack", "uberproxy-curl", "-s", url, "-X", method]

    if not content is None:
        cmdline += ["--data", content]

    for header_key in headers:
        cmdline += ["-H", f"{header_key}: {headers[header_key]}"]

    process = subprocess.Popen(cmdline, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    return process.stdout.read()


def get_artifact_dir():
    try:
        cibot_artifact_dir = os.environ['CIBOT_ARTIFACT_DIR']
        return cibot_artifact_dir
    except KeyError as e:
        print("[-] CIBOT_ARTIFACT_DIR isn't set!")


def set_filenames():
    global cibot_artifact_dir, checkpoint_json_out
    global checkpoint_text_result, checkpoint_fprm_out
    global checkpoint_original_out
    cibot_artifact_dir = get_artifact_dir()
    checkpoint_json_out = str(cibot_artifact_dir) + "/checkpoint_results.json"
    checkpoint_text_result = str(cibot_artifact_dir) + "/report.txt"
    checkpoint_fprm_out = str(cibot_artifact_dir) + "/fprm-result.json"
    checkpoint_original_out = str(cibot_artifact_dir) + "/original-result.json"


def open_json(filename):
    with open(filename, "r") as file:
        return json.load(file)


def semgrep_path_to_relative_path(path):
    """
    Path from the semgrep scan are formated as:
        repositories/repoName/file/to/path.ext
    The relative path of the file is:
        file/to/path.ext
    """
    return path.split("/", 2)[-1]


def create_checkpoint_results_json(results):
    set_filenames()
    with open(checkpoint_json_out, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=4)


def convert(fp_removed_filename, original_filename, comparison_filename):
    set_filenames()
    print(f"[+] Checkpoint artifacts dir: {cibot_artifact_dir}")
    fp_removed_data = open_json(fp_removed_filename)
    comparison_data = open_json(comparison_filename)
    original_data = open_json(original_filename)
    is_failure = "results" in fp_removed_data.keys() and len(fp_removed_data["results"]) > 0

    checkpoint_output = json.dumps({"original": original_data, "comparison": comparison_data})

    # Copy the original results as artifact for archival purpose
    shutil.copy(fp_removed_filename, checkpoint_fprm_out)
    shutil.copy(original_filename, checkpoint_original_out)

    # Mark the test case "semgrep-scan-non-blocking" as "failed" or "pass" depending on whether we have findings or not.
    out = [
        {"level": "failure" if is_failure else "pass", "case": "semgrep-scan-non-blocking", "output": checkpoint_output}
    ]
    create_checkpoint_results_json(out)

    # Generate a human readable version of the results so that people can see what vulnerabilities were found.
    with open(checkpoint_text_result, "w", encoding="utf-8") as f:
        content = "########################\n"
        content += "# Vulnerability report #\n"
        content += "########################\n"
        content += "\n"

        if not is_failure:
            content += "Tests passed. No new vulnerability identified.\n\n"
        else:
            content += "Tests failed. See the information below for more information.\n\n"

            for issue in fp_removed_data["results"]:
                path_in_project = semgrep_path_to_relative_path(issue["path"])
                command_mark_as_fp = "slack request-not-vulnerable "
                command_mark_as_fp += f"--hash_id={issue['hash_id']} "
                command_mark_as_fp += f"--location=\"{path_in_project}#{issue['start']['line']}\" "
                command_mark_as_fp += f"--language={fp_removed_data['metadata']['language']} "
                command_mark_as_fp += f"--repo_name={fp_removed_data['metadata']['repoName']} "
                command_mark_as_fp += "--message=\"{}\" ".format(
                    issue['extra']['message'].replace('\"', '\'').replace('`', '\'').replace('\n', ' ')
                )
                command_mark_as_fp += f"--check_id={issue['check_id']} "

                content += "----------------------\n"
                content += "Rule : {}\n".format(issue["check_id"])
                content += "Location : {}\n".format(path_in_project + ":" + str(issue["start"]["line"]))
                content += "Affected lines : {}\n".format(issue["extra"]["lines"])
                content += "Message : {}\n".format(issue["extra"]["message"])
                content += "\n"
                content += "Request to be marked as not vulnerable (command line) : {}\n".format(command_mark_as_fp)

            content += "----------------------"

        f.write(content)


def upload_pr_scan(branch, master):
    current_time = int(time.time())

    originals = set()
    for file in glob.glob(f"{RESULTS_DIR}/*.json"):
        prefix = file.split('-')[0:-1]
        prefix = '-'.join(prefix)
        # Only upload files from the master and branch scans
        if branch[:7] in prefix or master[:7] in prefix:
            originals.add(f"{prefix}.json")

    for semgrep_output_file in originals:
        with open(semgrep_output_file, "r") as f:
            semgrep_content = json.load(f)

        comparison_filename = semgrep_output_file.replace(".json", "-parsed.json")
        if os.path.exists(comparison_filename):
            with open(comparison_filename, "r") as f:
                semgrep_comparison_content = json.load(f)
        else:
            semgrep_comparison_content = {"results": []}

        is_failure = len(semgrep_content["results"]) > 0
        output_data = json.dumps({"original": semgrep_content, "comparison": semgrep_comparison_content})

        exit_code = upload_test_result_to_checkpoint(
            test_name=f"semgrep-scan-pr",
            output_data=output_data,
            repo=f'ghc/tinyspeck/{semgrep_content["metadata"]["repoName"]}',
            date_started=current_time,
            date_finished=current_time,
            branch="master",
            commit_head=branch,
            commit_master=master,
            is_failure=is_failure,
        )
    return exit_code


def upload_test_result_to_checkpoint(
    test_name, output_data, repo, date_started, date_finished, branch, commit_head, commit_master, is_failure
):
    tsauth_auth_token = get_tsauth_auth_token()

    if (not tsauth_auth_token or tsauth_auth_token.strip() == "") and not uberproxy_curl_installed():
        text = """:banger-alert: :snowflake:Daily :block-s: :block-e: :block-m: :block-g: :block-r: :block-e: :block-p: Scan Error:snowflake::banger-alert:\nTSAuth token couldn't be found. We can't upload results to checkpoint !"""
        cmd = f"echo \"{text}\" | slack --channel={CONFIG['general']['alertchannel']} --cat --user=SNOW "
        subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        print(
            "No TSAuth token found. The results of this scan won't be uploaded to"
            " checkpoint. Please reach out to #triage-prodsec if you see this error"
            " message."
        )
        return 1

    test_results = {
        "test_run": {
            "test_name": test_name,
            "repo": repo,
            "state": "failure" if is_failure else "success",
            "commit_head": commit_head,
            "commit_master": commit_master,
            "date_started": date_started,
            "date_finished": date_finished,
            "cibot_worker": "",  # Empty, this job is not ran as a CI job
            "ci_job_link": "",  # Empty, this job is not ran as a CI job
            "branch": branch,
            "check_flakiness": False,
        },
        "test_results": [
            {
                "case": test_name,
                "level": "failure" if is_failure else "pass",
                "owner": [""],  # Empty value, not used
                "duration": 0,  # Default value, we don't store any performance metrics for daily scan
                "output": output_data,
                "filename": "",  # Empty value, the results aren't specific to a file
                "line": 0,  # Empty value, the results aren't specific to a file
            }
        ],
    }
    url_stub = "/api/v1/testrun/import"
    call_result = call_checkpoint_api(url_stub, test_results, tsauth_auth_token)

    if call_result["ok"] == False:
        clean_error_results = call_result['error'].replace('\"', '').replace('`', '').replace('$', '')
        text = """:banger-alert: :snowflake:Daily :block-s: :block-e: :block-m: :block-g: :block-r: :block-e: :block-p: Scan Error:snowflake::banger-alert:\nCheckpoint results upload failed: """
        cmd = (
            f"echo \"{text}{clean_error_results}\" | slack"
            f" --channel={CONFIG['general']['alertchannel']} --cat --user=SNOW "
        )
        subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        print(f"Error while uploading results to checkpoint: {call_result['error']}")
        return 1
    return 0


def upload_daily_scan_results_to_checkpoint():
    current_time = int(time.time())

    originals = set()
    for file in glob.glob(f"{RESULTS_DIR}/*.json"):
        prefix = file.split('-')[0:-1]
        originals.append(f"{prefix}.json")

    for semgrep_output_file in originals:
        with open(semgrep_output_file, "r") as f:
            semgrep_content = json.load(f)

        comparison_filename = semgrep_output_file.replace(".json", "-comparison.json")
        if os.path.exists(comparison_filename):
            with open(comparison_filename, "r") as f:
                semgrep_comparison_content = json.load(f)
        else:
            semgrep_comparison_content = {"results": []}

        is_failure = len(semgrep_content["results"]) > 0
        output_data = json.dumps({"original": semgrep_content, "comparison": semgrep_comparison_content})

        exit_code = upload_test_result_to_checkpoint(
            test_name=f"semgrep-scan-daily-{jenkins.get_job_enviroment()}",
            output_data=output_data,
            repo=f'ghe/slack/{semgrep_content["metadata"]["repoName"]}',
            date_started=current_time,
            date_finished=current_time,
            branch="master",
            commit_head=semgrep_content["metadata"]["branch"],
            commit_master=semgrep_content["metadata"]["branch"],
            is_failure=is_failure,
        )
    return exit_code


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Converts a semgrep JSON result to checkpoint json out")
    parser.add_argument(
        "-f", "--false_positive_out", help="json comparison file from semgrep output with false positives removed"
    )
    parser.add_argument("-o", "--original_out", help="json file from semgrep output")
    parser.add_argument("-c", "--comparison_out", help="json file comparison from semgrep output")
    args = parser.parse_args()
    convert(args.false_positive_out, args.original_out, args.comparison_out)
