import json
import argparse
import os
CIBOT_ARTIFACT_DIR = os.getenv('CIBOT_ARTIFACT_DIR')
CHECKPOINT_JSON_OUT = str(CIBOT_ARTIFACT_DIR)+"/checkpoint_results.json"

def open_json(filename):
    with open(filename, "r") as file:
        data = json.load(file)
        file.close()
    return data


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
                new_issue["filename"] = issue["path"]
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
    args = parser.parse_args()
    convert(args.semgrep_out)
