#!/usr/bin/env python3
# -*- coding: future_fstrings -*-

import csv
import argparse
import sys
import json
import os.path

parser = argparse.ArgumentParser(
    description="Generates the false positives files."
)

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

        # Only check the finding that are marked as false positive.
        if not finding["Status"].strip().upper() == "FP":
            continue

        false_positive += 1
        hash_id = finding["HashId"].strip()

        if hash_id == "":
            print("[WARNING] Line {} is marked as a false positive, but doesn't contain a hash id. Can't add this false positives !".format(line))
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
            "message" : "Rule '{}' triggered.".format(finding["Rule"]),
            "check_id" : finding["Rule"],
            "location" : finding["Path"],
            "reason" : finding["Notes"]
        }

        with open(path_false_positive_file, "w") as f:
            json.dump(existing_data, f, indent=4)

        nb_added += 1

final_message = "[INFO] Processed {} lines in the file {}. False positive found : {}. New entry : {}. Duplicate : {}."
print(final_message.format(line, args.file, false_positive, nb_added, nb_duplicate))
