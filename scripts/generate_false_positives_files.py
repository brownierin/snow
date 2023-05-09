#!/usr/bin/env python3


import csv
import argparse
import json
import yaml
import os.path
import glob


def get_long_rule_id(check_id):
    for yaml_file in glob.glob(f"languages/{language}/**/*.yaml", recursive=True):
        with open(yaml_file, "r") as f:
            definition_content = yaml.safe_load(f)

            for rule in definition_content["rules"]:
                if check_id == rule["id"]:
                    return os.path.dirname(yaml_file).replace("/", ".") + "." + check_id

    raise Exception(f"Unknown check id : {check_id}")


parser = argparse.ArgumentParser(description="Generates the false positives files.")

parser.add_argument(
    "-f",
    "--file",
    help="path to the result file that contains triage information",
)

args = parser.parse_args()

line = 1
false_positive = 0
nb_duplicate = 0
nb_added = 0

with open(args.file, "r", encoding="utf-8") as csvfile:
    for finding in csv.DictReader(csvfile):
        line += 1

        # Only check the finding that are marked as false positive in the "Final Assessment" column
        if not "false positive" in finding["Final Assessment"].lower():
            continue

        false_positive += 1
        hash_id = finding["HashId"].strip()

        if finding["Security Notes"].strip() == "":
            print(
                "[WARNING] Line {} is marked as a false positive, but doesn't contain a note explaining the reason the finding is marked as a false positive. Can't add this false positives !".format(
                    line
                )
            )
            continue

        if hash_id == "":
            print(
                "[WARNING] Line {} is marked as a false positive, but doesn't contain a hash id. Can't add this false positives !".format(
                    line
                )
            )
            continue

        language = finding["Language"]
        project_name = finding["ProjectName"]
        path_false_positive_file = "languages/{}/false_positives/{}_false_positives.json".format(language, project_name)

        if not os.path.isfile(path_false_positive_file):
            with open(path_false_positive_file, "w") as f:
                f.write("{}")

        with open(path_false_positive_file, "r") as f:
            existing_data = json.load(f)

        # Finding is already marked as a false positive
        if hash_id in existing_data:
            nb_duplicate += 1
            continue

        existing_data[hash_id] = {
            "message": "Rule '{}' triggered.".format(finding["Rule and Remediation Guidance"]),
            "check_id": get_long_rule_id(finding["Rule and Remediation Guidance"]),
            "location": finding["Path"],
            "reason": finding["Security Notes"],
        }

        with open(path_false_positive_file, "w") as f:
            json.dump(existing_data, f, indent=4)
            f.write("\n")

        nb_added += 1

final_message = "[INFO] Processed {} lines in the file {}. False positive found : {}. New entry : {}. Duplicate : {}."
print(final_message.format(line, args.file, false_positive, nb_added, nb_duplicate))
