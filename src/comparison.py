#!/usr/bin/env python3

"""
How to run
==========
This script has two purposes:
    1. remove false positives from scan results.
        run with -r and the required commands.
    2. compare two scans and only keep new results
        run with -c and the required commands.

"""
import json
import argparse
import os
from collections import Counter, defaultdict
import logging

from src.exceptions import FalsePositiveFileDoesNotExist
from src.config import logger


def open_json(filename):
    data = {}
    with open(filename, "r") as file:
        data = json.load(file)
    return data


def write_json(filename, json_output):
    with open(filename, "w") as file:
        data = json.dumps(json_output, indent=4)
        file.write(data)


def open_false_positives(filename):
    false_positives = set()

    # When the false positive file doesn't exists we throw an error as this should never occur.
    if not os.path.exists(filename):
        raise FalsePositiveFileDoesNotExist(filename)

    data = open_json(filename)
    for fp in data:
        false_positives.add(fp)
    return false_positives


def remove_false_positives(json_filename, fp_filename, parsed_filename):
    """
    Removes false positives given a false positive file and semgrep scan results.
    Hash IDs are stored in a dict with the first 3 letters of the hash as the key.
    This helps keep lookups fast since we can just check for existence of the key.
    """
    data = open_json(json_filename)
    parsed = open_json(json_filename)
    fp = open_false_positives(fp_filename)
    for issue in data["results"]:
        hash_id = issue["hash_id"]
        if hash_id in fp:
            parsed["results"].remove(issue)
    write_json(parsed_filename, parsed)
    return parsed


def get_hash_ids(results: list) -> dict:
    new_data_struct = defaultdict(list)
    for result in results:
        new_data_struct[result["hash_id"]].append(result)
    return new_data_struct


def compare_to_last_run(old_output, new_output, output_filename):
    """
    This compares two scan runs to each other.
    It looks at a new scan run and an old scan run.
    It only keeps findings that are exclusively in the new run.
    """
    old = open_json(old_output)
    new = open_json(new_output)
    old_hashes = get_hash_ids(old["results"])
    new_hashes = get_hash_ids(new["results"])
    compare_number_of_same_hash_ids(old["results"], new["results"])

    """
    We're iterating this way to ensure we remove duplicated hash_ids, which
    can occur when code is copy-pasted within the same file.
    There's still an edge case when one scan result contains 1 finding and the
    next scan result contains 2 findings with the same hash_id
    This method will remove whichever finding comes first, which may not be the
    same as the new finding, but this is an improvement.
    """
    for finding in new_hashes:
        if finding in old_hashes:
            removal_number = get_num_of_findings_to_remove(old_hashes[finding], new_hashes[finding])
            for result in range(0, removal_number):
                new["results"].remove(new_hashes[finding][result])

    write_json(output_filename, new)
    return new


def get_num_of_findings_to_remove(old, new):
    """
    case: old findings have more
    old = 3
    new = 2
    we want to remove 2 from new (use new len)

    case: new findings have more
    old = 3
    new = 4
    we want to remove 3 from new (use old len)

    each time is the minimum, so minimum works
    """
    return min(len(new), len(old))


def check_hash_id_uniqueness(results):
    counts = Counter(result["hash_id"] for result in results)
    for k, v in counts.items():
        if v > 1:
            logging.warning(f"{k} has {v} results")
    return {k: v for k, v in counts.items() if v > 1}


def compare_number_of_same_hash_ids(old, new):
    old_counter = check_hash_id_uniqueness(old)
    new_counter = check_hash_id_uniqueness(new)
    if new_counter != old_counter:
        for k, v in new_counter.items():
            if k in old_counter.keys():
                if new_counter[k] != old_counter[k]:
                    logging.warning(
                        f"hash_id {k} has {v} instances in the new result but {old_counter[k]} in the old results. Watch for mismatches in the comparison process"
                    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Removes false positives from the final semgrep report.")
    parser.add_argument(
        "-fp", "--fp_filename", help="the list of false positives for a given repository. required for -r"
    )
    parser.add_argument(
        "-i", "--json_filename", help="the semgrep json data after hashes are assigned. required for -r"
    )
    parser.add_argument("-o", "--parsed_filename", help="the resulting output filename. required for -r")
    parser.add_argument("-od", "--output_diff", help="the file diff results are saved in. required for -c")
    parser.add_argument("-in", "--input_new", help="the file for the latest scan. required for -c")
    parser.add_argument("-io", "--input_old", help="the file for the previous scan to compare to. required for -c")
    parser.add_argument("-c", "--compare", action="store_true", help="compare a previous run to a new run")
    parser.add_argument(
        "-r", "--remove_false_positives", action="store_true", help="remove false positives from scan results"
    )
    args = parser.parse_args()
    if args.remove_false_positives and (
        args.fp_filename is None or args.json_filename is None or args.parsed_filename is None
    ):
        parser.error("-r requires -fp, -i, and -o.")
    elif args.remove_false_positives:
        remove_false_positives(args.json_filename, args.fp_filename, args.parsed_filename)
    if args.compare and (args.input_new is None or args.input_old is None or args.output_diff is None):
        parser.error("-c requires -io, -in, and -od.")
    elif args.compare:
        compare_to_last_run(args.input_old, args.input_new, args.output_diff)
