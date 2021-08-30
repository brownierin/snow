#!/usr/bin/env python3
# -*- coding: future_fstrings -*-

import json
import argparse
import os
import shutil

CIBOT_ARTIFACT_DIR = os.getenv('CIBOT_ARTIFACT_DIR')
CHECKPOINT_JSON_OUT = str(CIBOT_ARTIFACT_DIR)+"/checkpoint_results.json"
CHECKPOINT_TEXT_RESULT = str(CIBOT_ARTIFACT_DIR)+"/report.txt"
CHECKPOINT_FPRM_OUT = str(CIBOT_ARTIFACT_DIR)+"/fprm-result.json"
CHECKPOINT_ORIGINAL_OUT = str(CIBOT_ARTIFACT_DIR)+"/original-result.json"

def open_json(filename):
    with open(filename, "r") as file:
        return json.load(file)

# Path from the semgrep scan are formated as : repositories/repoName/file/to/path.ext
# While the relative path of the file is : file/to/path.ext
def semgrep_path_to_relative_path(path):
    return path.split("/", 2)[-1]

def create_checkpoint_results_json(results):
    with open(CHECKPOINT_JSON_OUT, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=4)

def convert(fp_removed_filename, original_filename, comparison_filename):
    fp_removed_data = open_json(fp_removed_filename)
    comparison_data = open_json(comparison_filename)
    original_data = open_json(original_filename)
    is_failure = "results" in fp_removed_data.keys() and len(fp_removed_data["results"]) > 0

    checkpoint_output = json.dumps({
        "original" : original_data,
        "comparison" : comparison_data
    })

    # Copy the original results as artifact for archival purpose
    shutil.copy(fp_removed_filename, CHECKPOINT_FPRM_OUT)
    shutil.copy(original_filename, CHECKPOINT_ORIGINAL_OUT)

    # Mark the test case "semgrep-scan-non-blocking" as "failed" or "pass" depending on whether we have findings or not.
    out = [{
        "level" : "failure" if is_failure else "pass",
        "case" : "semgrep-scan-non-blocking",
        "output" : checkpoint_output
    }]
    create_checkpoint_results_json(out)

    # Generate a human readable version of the results so that people can see what vulnerabilities were found.
    with open(CHECKPOINT_TEXT_RESULT, "w", encoding="utf-8") as f:
        content  = "########################\n"
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
                command_mark_as_fp += "--message=\"{}\" ".format(issue['extra']['message'].replace('\"','\'').replace('`','\'').replace('\n',' '))
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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Converts a semgrep JSON result to checkpoint json out"
    )
    parser.add_argument(
        "-f",
        "--false_positive_out",
        help="json comparison file from semgrep output with false positives removed",
    )
    parser.add_argument(
        "-o",
        "--original_out",
        help="json file from semgrep output",
    )
    parser.add_argument(
        "-c",
        "--comparison_out",
        help="json file comparison from semgrep output",
    )
    args = parser.parse_args()
    convert(args.false_positive_out, args.original_out, args.comparison_out)
