#!/usr/bin/env python3
# -*- coding: future_fstrings -*-

import json
import csv
import argparse
import os.path

def format_csv(json_files, out_csv):
    all_results = []

    for result_file_path in json_files:
        # Here we expect the filename to have the following format
        # language-project-name-hash.json OR
        # language-project-name-hash-type.json
        filename  =  os.path.basename(result_file_path)
        language, rest = filename.split("-", 1)

        with open(result_file_path) as result_file:
            result_data = json.load(result_file)
            project_name = result_data["metadata"]["repoName"]
            base_github_url = result_data["metadata"]["GitHubRepo"]
            git_branch = result_data["metadata"]["branch"]

            for finding in result_data["results"]:
                start_line = finding["start"]["line"]
                end_line = finding["end"]["line"]
                checkid = finding["check_id"]

                # The scanned path starts with repositories/repoName/ in the result file. We need to remove this.
                path = finding["path"]
                path = path.split("/", 2)[2]

                # hash_id is only available in "fprm" result file. We need to handle when it's missing
                hash_id = finding["hash_id"] if "hash_id" in finding else ""

                all_results.append({
                    "Rule" : checkid,
                    "ProjectName" : project_name,
                    "Language" : language,
                    "Path" : "{}/slack/{}/blob/{}/{}#L{}-L{}".format(base_github_url, project_name, git_branch, path, start_line, end_line),
                    "HashId" : hash_id
                })
    
    with open(out_csv, "w") as csvwrite:       
        writer = csv.DictWriter(csvwrite, fieldnames=["Rule", "ProjectName", "Language", "Path", "Checked", "Status", "Jira", "Notes", "HashId"])
        writer.writeheader()
        writer.writerows(all_results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Converts a result JSON file to CSV"
    )
    parser.add_argument(
        "json_files",
        nargs="+",
        help="List of all input JSON file",
    )
    parser.add_argument(
        "-o",
        "--out_filename",
        help="Output CSV file",
    )
    args = parser.parse_args()

    format_csv(args.json_files, args.out_filename)
