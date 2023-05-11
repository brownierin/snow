import os
import glob
import json

from src.config import SNOW_ROOT
from src.config import logger
from run_semgrep import get_repo_list, find_repo_language


def test_valid_false_positives_file():
    # Checks that all false positive file are valid
    all_fp_files = list(glob.glob(f"{SNOW_ROOT}/languages/*/false_positives/*_false_positives.json"))

    assert len(all_fp_files) > 0

    for file in all_fp_files:
        with open(file, "r") as f:
            data = json.load(f)
            assert isinstance(data, dict)


def test_no_missing_false_positive_file():
    # Checks that a false positive file exists for all enabled repo
    repos = get_repo_list()

    for repo_long in repos:
        language = find_repo_language(repo_long)
        url, org, repo = repo_long.split("/")
        fp_file = f"{SNOW_ROOT}/languages/{language}/false_positives/{repo}_false_positives.json"
        assert os.path.exists(fp_file), f"'{fp_file}' is missing"
