import json
import logging

from run_semgrep import process_one_result, remove_scheme_from_url
from src.config import SNOW_ROOT
from src.config import logger


def test_url_builder():
    with open(f"{SNOW_ROOT}/tests/fixtures/output.json") as f:
        results = json.load(f)
    result = results["results"][0]
    github_url = "https://slack-github.com"
    git_org = results["metadata"]["git_org"]
    repo_name = results["metadata"]["repo_name"]
    github_branch = "default"

    one_result = process_one_result(result, github_url, git_org, repo_name, github_branch)
    expected_url = "https://slack-github.com/slack/malware-service/tree/default/malware/filetypes.go#L99"
    assert expected_url in one_result[0]
    assert 1 == one_result[1]


def test_remove_url_scheme():
    repo_url = "https://slack-github.com/slack/checkpoint.git"
    expected_url = "slack-github.com/slack/checkpoint"

    repo = remove_scheme_from_url(repo_url)
    assert expected_url == repo
    assert "https://" not in repo
    assert not repo.endswith(".git")
