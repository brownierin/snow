import json
import argparse
import logging

"""
How to run
==========
This script has two purposes:
    1. remove false positives from scan results.
        run with -r and the required commands.
    2. compare two scans and only keep new results
        run with -c and the required commands.

"""


def open_json(filename):
    with open(filename, "r") as file:
        data = json.load(file)
        file.close()
    return data


def write_json(filename, json_output):
    with open(filename, "w") as file:
        data = json.dumps(json_output)
        file.write(data)
        file.close()


def open_false_positives(filename):
    with open(filename) as file:
        read_in = file.readlines()
        file.close()
    false_positives = {}
    for line in read_in:
        try:
            false_positives[line[:3]].append(line)
        except:
            false_positives[line[:3]] = [line]
    return false_positives


def remove_false_positives(json_filename, fp_filename, parsed_filename):
    """
    Removes false positives given a false positive file and semgrep scan results.
    Hash IDs are stored in a dict with the first 3 letters of the hash as the key.
    This helps keep lookups fast since we can just check for existence of the key.
    """
    data = open_json(json_filename)
    fp = open_false_positives(fp_filename)
    for issue in data["results"]:
        hash_id = issue["hash_id"]
        if fp[hash_id[:3]]:
            for fp_hash_id in fp[hash_id[:3]]:
                if fp_hash_id == hash_id:
                    data["results"].remove(issue)
    write_json(parsed_filename, data)
    return data


def get_hash_ids(data):
    hash_ids = {}
    for issue in data["results"]:
        hash_id = issue["hash_id"]
        try:
            hash_ids[hash_id[:3]].append(hash_id)
        except:
            hash_ids[hash_id[:3]] = [hash_id]
    return hash_ids


def compare_to_last_run(old_output, new_output, output_filename):
    """
    This compares two scan runs to each other.
    It looks at a new scan run and an old scan run.
    It only keeps findings that are exclusively in the new run.
    """
    old = open_json(old_output)
    new = open_json(new_output)
    old_hashes = get_hash_ids(old)
    new_hashes = get_hash_ids(new)
    logging.info(f"old hashes: \n {old_hashes}")
    logging.info(f"new hashes: \n {new_hashes}")
    if old_hashes == new_hashes:
        new["results"].clear()
        new["results"] = "No new findings"
        write_json(output_filename, new)
        return new

    for hashes in new_hashes.values():
        for new_issue_hash in hashes:
            logging.info(f"current hash: {new_issue_hash}")
            try:
                bucket = old_hashes[new_issue_hash[:3]]
                for old_hash in bucket:
                    if old_hash == new_issue_hash:
                        [
                            new["results"].remove(issue)
                            for issue in new["results"]
                            if issue["hash_id"] == new_issue_hash
                        ]
                        logging.info(f"removing issue {new_issue_hash}")
            except:
                continue
    write_json(output_filename, new)
    return new


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Removes false positives from the final semgrep report."
    )
    parser.add_argument(
        "-fp",
        "--fp_filename",
        help="the list of false positives for a given repository. required for -r",
    )
    parser.add_argument(
        "-i",
        "--json_filename",
        help="the semgrep json data after hashes are assigned. required for -r",
    )
    parser.add_argument(
        "-o", "--parsed_filename", help="the resulting output filename. required for -r"
    )
    parser.add_argument(
        "-od",
        "--output_diff",
        help="the file diff results are saved in. required for -c",
    )
    parser.add_argument(
        "-in", "--input_new", help="the file for the latest scan. required for -c"
    )
    parser.add_argument(
        "-io",
        "--input_old",
        help="the file for the previous scan to compare to. required for -c",
    )
    parser.add_argument(
        "-c",
        "--compare",
        action="store_true",
        help="compare a previous run to a new run",
    )
    parser.add_argument(
        "-r",
        "--remove_false_positives",
        action="store_true",
        help="remove false positives from scan results",
    )
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    if args.remove_false_positives and (
        args.fp_filename is None
        or args.json_filename is None
        or args.parsed_filename is None
    ):
        parser.error("-r requires -fp, -i, and -o.")
    elif args.remove_false_positives:
        remove_false_positives(
            args.json_filename, args.fp_filename, args.parsed_filename
        )
    if args.compare and (
        args.input_new is None or args.input_old is None or args.output_diff is None
    ):
        parser.error("-c requires -io, -in, and -od.")
    elif args.compare:
        compare_to_last_run(args.input_new, args.input_old, args.output_diff)
