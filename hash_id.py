#!/usr/bin/env python3
import json
import hashlib

# How to run:
# docker run --rm -v "${PWD}:/src" --entrypoint "python" returntocorp/semgrep /src/hash.py

# Grab source codes. Also include one line above and one line below the issue location
def read_line(issue_file, line):
    with open(issue_file) as f:
        content = f.readlines()
        # check lines
        start = line - 2 if line - 2 > 0 else 0
        end = line + 1 if len(content) >= line + 1 else len(content)
        data = content[start:end]
    return "".join(data).replace("\n", "|")


# Function to add hash field to the semgrep json output as a unique id
# The hash is sha 256 value of : check_id + path + 3 line of codes
# NOTE: We don't hash the line number. Code addition could change the line number
def add_hash_id(jsonFile):
    # Open json file
    f = open(jsonFile, "r")
    data = json.load(f)
    f.close()

    for issue in data["results"]:

        # Check issue metadata
        if issue["path"] or issue["start"]["line"] is None:
            continue

        file_path = "/src/" + issue["path"]
        line = issue["start"]["line"]
        base_code = read_line(file_path, line)

        # Check line from out exist in the base_code
        if issue["extra"]["lines"] in base_code:
            base_hash = issue["check_id"] + "|" + file_path + "|" + base_code
        else:
            base_hash = (
                issue["check_id"] + "|" + file_path + "|" + issue["extra"]["lines"]
            )

        # Hash the base
        res = bytes(base_hash, "utf-8")
        hash_digest = hashlib.sha256(res).hexdigest()

        # Update the json blob
        issue["hash_id"] = hash_digest

    ## Save our changes to JSON file
    jsonFile = open(json_result, "w+")
    jsonFile.write(json.dumps(data))
    jsonFile.close()


# Main
# Post processing - just iterate to all of the json results to add the hash_id
json_result = "/src/results/results-golang-flannel.json"
add_hash_id(json_result)
