import os
import json
import sys

SNOW_ROOT = os.path.realpath(os.path.dirname(os.path.realpath(__file__)) + "/../../")

sys.path.insert(0,SNOW_ROOT)
from run_semgrep import process_one_result

def test_url_builder():
    with open(f"{SNOW_ROOT}/tests/fixtures/output.json") as f:
        results = json.load(f)
    result = results["results"][0]
    github_url = "https://slack-github.com/slack"
    repo_name = results["metadata"]["repoName"]
    github_branch = "default"

    one_result = process_one_result(result, github_url, repo_name, github_branch)
    expected = "https://slack-github.com/slack/malware-service/tree/default/malware/filetypes.go#L99"
    assert expected in one_result[0]
