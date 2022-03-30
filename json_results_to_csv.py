#!/usr/bin/env python3


import json
import csv
import argparse
import os.path
import glob
import yaml

def make_csv_link(url, text):
    return f'=HYPERLINK("{url}","{text}")'

def get_nice_checkid(language, check_id):
    for yaml_file in glob.glob(f"languages/{language}/**/*.yaml", recursive=True):
        with open(yaml_file, "r") as f:
            definition_content = yaml.safe_load(f)

            for rule in definition_content["rules"]:
                if check_id.endswith(rule["id"]):
                    url = f"https://slack-github.com/slack/snow/tree/master/{yaml_file}"
                    return make_csv_link(url, rule["id"])

    return check_id

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
            url_project = f"https://slack-github.com/slack/{project_name}/"

            for finding in result_data["results"]:
                if not "hash_id" in finding:
                    raise Exception(f"The result file '{result_file_path}' is missing the 'hash_id' field.")

                start_line = finding["start"]["line"]
                end_line = finding["end"]["line"]
                checkid = finding["check_id"]

                # The scanned path starts with repositories/repoName/ in the result file. We need to remove this.
                path = finding["path"]
                path = path.split("/", 2)[2]

                # hash_id is only available in "fprm" result file. We need to handle when it's missing
                hash_id = finding["hash_id"]

                all_results.append({
                    "Rule and Remediation Guidance" : get_nice_checkid(language, checkid),
                    "ProjectName" : make_csv_link(url_project, project_name),
                    "Language" : language,
                    "Path" : f"{base_github_url}/slack/{project_name}/blob/{git_branch}/{path}#L{start_line}-L{end_line}",
                    "HashId" : hash_id
                })
    
    with open(out_csv, "w") as csvwrite:       
        writer = csv.DictWriter(csvwrite, fieldnames=[
            "Rule and Remediation Guidance",
            "ProjectName",
            "Language",
            "Initial Assessment",
            "Dev Contact",
            "Dev Assessment",
            "Dev Notes on Assesment Decision",
            "Final Assessment",
            "JIRA Ticket",
            "Security Notes",
            "Path",
            "HashId"
        ])
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
