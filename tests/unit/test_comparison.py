import os
import sys
import json
import logging
from unittest.mock import patch, mock_open
from io import StringIO

SNOW_ROOT = os.path.realpath(os.path.dirname(os.path.realpath(__file__)) + "/../../")
sys.path.insert(0, SNOW_ROOT)

import src.comparison as comparison


def create_result(hash_id: str) -> dict:
    result = {
        "check_id": "languages.fake",
        "extra": {
            "is_ignored": "false",
            "lines": "fake",
            "message": "this is a fake writeup\n",
            "metadata": {},
            "metavars": {},
            "severity": "WARNING",
        },
        "path": "repositories/fake_repo/fake.py",
        "hash_id": hash_id,
    }
    return result


def generate_results(hash_ids: list) -> dict:
    results = [create_result(hash_id) for hash_id in hash_ids]

    return {"errors": [], "metadata": {}, "results": results}


def test_compare_to_last_run_diff_results():
    old_hash = "ff65191189bc92514ee9c4fbf64988f3f3e88565b4e29e418840b99b593b7e56"
    new_hash = "ab65191189bc92514ee9c4fbf64988f3f3e88565b4e29e418840b99b593b7123"
    output_filename = "output.json"
    old_results = json.dumps(generate_results([old_hash]))
    new_results = json.dumps(generate_results([new_hash]))

    with patch("builtins.open", side_effect=[StringIO(old_results), StringIO(new_results), StringIO("")]):
        # We're not using the output file from the comparison, we're using the return value of the function
        # So it's fine to stub it out for these tests
        with patch(
            "src.comparison.open_json", side_effect=[json.loads(old_results), json.loads(new_results)]
        ) as mock_open_json:
            output = comparison.compare_to_last_run("old.json", "new.json", output_filename)
            mock_open_json.assert_any_call("old.json")
            mock_open_json.assert_any_call("new.json")

    # check that only the new finding was kept
    assert len(output["results"]) == 1
    assert output["results"][0]["hash_id"] == "ab65191189bc92514ee9c4fbf64988f3f3e88565b4e29e418840b99b593b7123"

    # check that old finding was removed
    assert output["results"][0]["hash_id"] != "ff65191189bc92514ee9c4fbf64988f3f3e88565b4e29e418840b99b593b7e56"


def test_compare_to_last_run_repeated_results():
    old_hash = "ff65191189bc92514ee9c4fbf64988f3f3e88565b4e29e418840b99b593b7e56"
    new_hash = "ab65191189bc92514ee9c4fbf64988f3f3e88565b4e29e418840b99b593b7123"
    output_filename = "output.json"
    old_results = json.dumps(generate_results([old_hash, new_hash]))
    new_results = json.dumps(generate_results([new_hash, new_hash]))

    with patch("builtins.open", side_effect=[StringIO(old_results), StringIO(new_results), StringIO("")]):
        # We're not using the output file from the comparison, we're using the return value of the function
        # So it's fine to stub it out for these tests
        with patch(
            "src.comparison.open_json", side_effect=[json.loads(old_results), json.loads(new_results)]
        ) as mock_open_json:
            output = comparison.compare_to_last_run("old.json", "new.json", output_filename)
            mock_open_json.assert_any_call("old.json")
            mock_open_json.assert_any_call("new.json")

    # check that only one finding was kept
    assert len(output["results"]) == 1
    assert output["results"][0]["hash_id"] == "ab65191189bc92514ee9c4fbf64988f3f3e88565b4e29e418840b99b593b7123"

    # check that old finding was removed
    assert output["results"][0]["hash_id"] != "ff65191189bc92514ee9c4fbf64988f3f3e88565b4e29e418840b99b593b7e56"


def test_compare_to_last_run_duplicated_results():
    new_hash = "ab65191189bc92514ee9c4fbf64988f3f3e88565b4e29e418840b99b593b7123"
    output_filename = "output.json"
    old_results = json.dumps(generate_results([new_hash, new_hash]))
    new_results = json.dumps(generate_results([new_hash, new_hash]))

    with patch("builtins.open", side_effect=[StringIO(old_results), StringIO(new_results), StringIO("")]):
        # We're not using the output file from the comparison, we're using the return value of the function
        # So it's fine to stub it out for these tests
        with patch(
            "src.comparison.open_json", side_effect=[json.loads(old_results), json.loads(new_results)]
        ) as mock_open_json:
            output = comparison.compare_to_last_run("old.json", "new.json", output_filename)
            mock_open_json.assert_any_call("old.json")
            mock_open_json.assert_any_call("new.json")

    # no findings should be kept
    assert len(output["results"]) == 0
