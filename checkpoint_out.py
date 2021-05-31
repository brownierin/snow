#!/usr/bin/env python3
# -*- coding: future_fstrings -*-

import json
import argparse
import os
CIBOT_ARTIFACT_DIR = os.getenv('CIBOT_ARTIFACT_DIR')
CHECKPOINT_JSON_OUT = str(CIBOT_ARTIFACT_DIR)+"/checkpoint_results.json"

def open_json(filename):
    with open(filename, "r") as file:
        return json.load(file)

# Path from the semgrep scan are formated as : repositories/repoName/file/to/path.ext
# While the relative path of the file is : file/to/path.ext
def semgrep_path_to_relative_path(path):
    return path.split("/", 2)[-1]

def add_false_positive_info(fp_removed_filename, original_filename):
    if os.path.exists(CHECKPOINT_JSON_OUT):
        original_data = open_json(CHECKPOINT_JSON_OUT)
    else:
        original_data = []
    
    fp_removed_data = open_json(fp_removed_filename)
    all_data = open_json(original_filename)

    if not "results" in fp_removed_data:
        fp_removed_data["results"] = []

    # Map to check if an hash_id exists in the fp_removed file
    fp_remove_hash_id_map = {}
    for issue in fp_removed_data["results"]:
        fp_remove_hash_id_map[issue["hash_id"]] = True

    with open(CHECKPOINT_JSON_OUT, "w", encoding="utf-8") as f:
        if "results" in all_data:
            for issue in all_data["results"]:
                # If the finding is not marked as a false positive, we don't keep it
                if issue["hash_id"] in fp_remove_hash_id_map:
                    continue
                
                # False positives are marked as "info" test cases, so that we can see the 
                # test cases and make sure they won't fail the semgrep tests.
                new_issue = {}
                new_issue["case"] = str(issue["check_id"])
                new_issue["output"] = "Issue was marked as a false positive"
                new_issue["level"] = "info"
                new_issue["filename"] = semgrep_path_to_relative_path(issue["path"])
                new_issue["line"] = int(issue["start"]["line"])

                original_data.append(new_issue)

        json.dump(original_data, f, ensure_ascii=False, indent=4)

def convert(fp_removed_filename):
    data = open_json(fp_removed_filename)
    with open(CHECKPOINT_JSON_OUT, "w", encoding="utf-8") as f:
        out = []
        if "results" in data.keys():
            for issue in data["results"]:
                new_issue = {}
                new_issue["case"] = str(issue["check_id"])
                new_issue["level"] = "failure"
                new_issue["output"] = "Message: " + issue["extra"]["message"]
                new_issue["output"] += "\nLocation: " + issue["path"] + ":" + str(issue["start"]["line"])
                new_issue["output"] += "\nLines: " + issue["extra"]["lines"]
                new_issue["output"] += "\nMetadata: " + json.dumps(issue["extra"]["metadata"],indent = 1)
                new_issue["output"] += "\nSeverity: " + issue["extra"]["severity"]
                new_issue["filename"] = semgrep_path_to_relative_path(issue["path"])
                new_issue["line"] = int(issue["start"]["line"])
                out.append(new_issue)
        json.dump(out, f, ensure_ascii=False, indent=4)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Converts a semgrep JSON result to checkpoint json out"
    )
    parser.add_argument(
        "-s",
        "--semgrep_out",
        help="json file from semgrep output with false positives removed",
    )
    parser.add_argument(
        "-o",
        "--semgrep_original_out",
        help="json file from semgrep output with the false positives",
    )
    args = parser.parse_args()
    convert(args.semgrep_out)

    if args.semgrep_original_out:
        add_false_positive_info(args.semgrep_out, args.semgrep_original_out)
