#!/usr/bin/env python3
# -*- coding: future_fstrings -*-

import csv
import argparse
import sys

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Runs the difference between two sets of scan results to get the new findings only."
    )
    parser.add_argument(
        "-o",
        "--old",
        help="path to the old scan result",
    )
    parser.add_argument(
        "-n",
        "--new",
        help="path to the new scan result",
    )

    args = parser.parse_args()

    writer = csv.DictWriter(sys.stdout, fieldnames=["Rule", "ProjectName", "Language", "Path", "Checked", "Status", "Jira", "Notes", "HashId"])
    writer.writeheader()

    old_findings = {}
    with open(args.old, "r", encoding="utf-8") as csvfile:
        for old_finding in csv.DictReader(csvfile):
            key = old_finding["HashId"]
            old_findings[key] = old_finding

    with open(args.new, "r", encoding="utf-8") as csvfile:
        for new_finding in csv.DictReader(csvfile):
            key = new_finding["HashId"]

            if not key in old_findings:
                writer.writerow(new_finding)
