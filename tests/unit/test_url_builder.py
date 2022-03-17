import os
import json
import sys
import logging
import pytest

logger = logging.getLogger(__name__)

SNOW_ROOT = os.path.realpath(os.path.dirname(os.path.realpath(__file__)) + "/../../")

sys.path.insert(0,SNOW_ROOT)
from run_semgrep import process_one_result, set_github_full_url

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
    assert 1 == one_result[1]

# @pytest.fixture(autouse=True)
def test_org_builder():
    github_url = "https://github.com"

    expected = "https://github.com/tinyspeck"
    full_url = set_github_full_url(github_url)

    assert full_url == expected
