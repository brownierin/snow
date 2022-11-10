#! /usr/bin/env python3

from select import select
import src.comparison as comparison
from run_semgrep import add_hash_id
import shutil


def add_identifiers(output_file_path):
    add_hash_id(output_file_path, 4, 1, "hash_id")

def add_identifier_to_multiple_files(filenames):
    for file in filenames:
        add_identifiers(file)

def make_backup(filenames):
    for file in filenames:
        print(file)
        backup_filename = f"{file}.back"
        shutil.copyfile(file, backup_filename)

def compare(filenames):
    comparison.compare_to_last_run(filenames[0], filenames[1], "comparison.json")

def select_by_path(filenames):
    for file in filenames:
        data = comparison.open_json(file)
        results = data["results"]
        path = "repositories/chef-repo/slackops3/src/slackops/bin/dish-pig.py"
        sorted = [result for result in results if result["path"] == path]
        # print(sorted)
        comparison.write_json(f"{file}-dish-pig", sorted)

def select_hash_ids(filenames):
    filenames = [f"{file}-dish-pig" for file in filenames]
    for file in filenames:
        data = comparison.open_json(file)
        print(file)
        for result in data:
            print(result["hash_id"])

if __name__ == "__main__":
    filenames = ["results/python-chef-repo-2bb0371.json", "results/python-chef-repo-006fee1.json"]
    print(filenames)
    make_backup(filenames)
    add_identifier_to_multiple_files(filenames)
    compare(filenames)
    select_by_path(filenames)
    select_hash_ids(filenames)

