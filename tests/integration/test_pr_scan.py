# -*- coding: future_fstrings -*-

import os
import shutil
import json
import tempfile
import subprocess


"""
TEST SETUP UTILITY - START
"""

SNOW_ROOT = os.path.realpath(os.path.dirname(os.path.realpath(__file__)) + "/../../")
TEST_FOLDER = os.path.dirname(os.path.realpath(__file__))


def setup_test_case(test_name, language, false_postive={}):
    # Ensure the repositories folder exists
    if not os.path.exists(f"{SNOW_ROOT}/repositories/"):
        os.mkdir(f"{SNOW_ROOT}/repositories/")

    temp_folder = f"{SNOW_ROOT}/repositories/{test_name}/"
    source_folder = f"{TEST_FOLDER}/{test_name}"

    # If the temp folder still exists, this is likely to be something that stayed there from
    # previous run. We shouldn't keep it.
    if os.path.exists(temp_folder):
        shutil.rmtree(temp_folder)

    os.mkdir(temp_folder)

    # Create an empty git local repo
    subprocess.run(f"git -C {temp_folder} init", shell=True)
    revision = {}

    # Create all the revision of the local repo
    for subfolder in sorted(os.listdir(source_folder)):
        subprocess.run(f"cp -r {source_folder}/{subfolder}/* {temp_folder}", shell=True)
        subprocess.run(f"git -C {temp_folder} add .", shell=True)
        subprocess.run(f"git -C {temp_folder} commit -m {subfolder}", shell=True)
        commit_hash = subprocess.Popen(
            f"git -C {temp_folder} show -s --format=%H", stdout=subprocess.PIPE, shell=True
        ).stdout.read()
        commit_hash = commit_hash.strip()
        revision[subfolder] = commit_hash

    # Make the temp project "enabled"
    with open(f"{SNOW_ROOT}/languages/{language}/enabled", "a") as f:
        f.write(test_name + "\n")

    # Create the false positives file of the temp project
    with open(f"{SNOW_ROOT}/languages/{language}/false_positives/{test_name}_false_positives.json", "w") as f:
        json.dump(false_postive, f, indent=4)

    return revision


def take_down_case(test_name, language):
    # Clean temp project
    temp_folder = f"{SNOW_ROOT}/repositories/{test_name}/"
    shutil.rmtree(temp_folder)

    # Remove the temp project from enabled file
    with open(f"{SNOW_ROOT}/languages/{language}/enabled", "r") as f:
        content = f.read()
        content = content.replace(test_name + "\n", "")

    with open(f"{SNOW_ROOT}/languages/{language}/enabled", "w") as f:
        f.write(content)

    # Remove the false postives file
    os.remove(f"{SNOW_ROOT}/languages/{language}/false_positives/{test_name}_false_positives.json")


def do_scan(test_name, pr_commit, master_commit):
    with tempfile.TemporaryDirectory() as checkpoint_out_dir:
        with tempfile.TemporaryDirectory() as snow_fake_dir:
            os.mkdir(snow_fake_dir + "/repos/")

            snow_dir = f"{snow_fake_dir}/repos/snow/"
            repo_dir = f"{snow_fake_dir}/current/"
            repo_origin_dir = f"{SNOW_ROOT}/repositories/{test_name}/"

            shutil.copytree(SNOW_ROOT, snow_dir, ignore=shutil.ignore_patterns("repositories"))
            os.mkdir(f"{snow_dir}/repositories/")
            shutil.copytree(repo_origin_dir, repo_dir)
            shutil.copytree(f"{repo_origin_dir}", f"{repo_dir}{test_name}/")

            cmd_env = os.environ.copy()
            cmd_env["CIBOT_REPO"] = f"https://slack-github.com/slack/{test_name}.git"
            cmd_env["CIBOT_ARTIFACT_DIR"] = checkpoint_out_dir
            cmd_env["CIBOT_COMMIT_HEAD"] = pr_commit
            cmd_env["CIBOT_COMMIT_MASTER"] = master_commit

            process = subprocess.run(["../repos/snow/semgrep-checkpoint-pr.sh"], env=cmd_env, cwd=repo_dir)

            checkpoint_out_result = {}
            checkpoint_out_result["exit_code"] = process.returncode

            for artefact in os.listdir(checkpoint_out_dir):
                with open(f"{checkpoint_out_dir}/{artefact}", "r") as f:
                    checkpoint_out_result[artefact] = f.read()

            return checkpoint_out_result


"""
TEST SETUP UTILITY - START - END
"""

"""
TEST CASES - START
"""

# Base case where there one finding and master doesn't have any
def test_pr_scan_base_case():
    test_name = "pr_scan_base_case"
    test_lang = "golang"

    revision = setup_test_case(test_name, test_lang)
    checkpoint_output = do_scan(test_name, revision["1_pr"], revision["0_master"])

    assert "checkpoint_results.json" in checkpoint_output

    checkpoint_result = json.loads(checkpoint_output["checkpoint_results.json"])

    assert len(checkpoint_result) == 1
    assert checkpoint_result[0]["case"] == "semgrep-scan-non-blocking"
    assert checkpoint_result[0]["level"] == "failure"

    output = json.loads(checkpoint_result[0]["output"])

    assert len(output["comparison"]["results"]) == 1
    assert output["comparison"]["results"][0]["check_id"] == "languages.golang.slack.potential-code-execution-1"

    assert checkpoint_output["exit_code"] > 0

    take_down_case(test_name, test_lang)


# Test case where master contains one vulnerability and pr contains a new one
def test_pr_scan_report_new_vuln_only():
    test_name = "pr_scan_report_new_vuln_only"
    test_lang = "golang"

    revision = setup_test_case(test_name, test_lang)
    checkpoint_output = do_scan(test_name, revision["1_pr"], revision["0_master"])

    assert "checkpoint_results.json" in checkpoint_output

    checkpoint_result = json.loads(checkpoint_output["checkpoint_results.json"])

    assert len(checkpoint_result) == 1
    assert checkpoint_result[0]["case"] == "semgrep-scan-non-blocking"
    assert checkpoint_result[0]["level"] == "failure"

    output = json.loads(checkpoint_result[0]["output"])

    assert len(output["comparison"]["results"]) == 1
    assert (
        output["comparison"]["results"][0]["check_id"] == "languages.golang.r2c.go.lang.security.bad-tmp-file-creation"
    )

    assert checkpoint_output["exit_code"] > 0

    take_down_case(test_name, test_lang)


# Test case where the pr contains no new vulnerability that isn't in master
def test_pr_scan_no_new_vuln():
    test_name = "pr_scan_no_new_vuln"
    test_lang = "golang"

    revision = setup_test_case(test_name, test_lang)
    checkpoint_output = do_scan(test_name, revision["1_pr"], revision["0_master"])

    assert "checkpoint_results.json" in checkpoint_output

    checkpoint_result = json.loads(checkpoint_output["checkpoint_results.json"])

    assert len(checkpoint_result) == 1
    assert checkpoint_result[0]["case"] == "semgrep-scan-non-blocking"
    assert checkpoint_result[0]["level"] == "pass"

    output = json.loads(checkpoint_result[0]["output"])

    assert len(output["comparison"]["results"]) == 0

    assert checkpoint_output["exit_code"] == 0

    take_down_case(test_name, test_lang)


# Test case with false positive to suppress
def test_pr_with_false_positives():
    test_name = "pr_with_false_positives"
    test_lang = "golang"

    false_positives = {
        "5809d6e3655e6771ffdf271998e39ab7545553e858d2c95817603f262d88a404": {
            "message": "Rule 'languages.golang.slack.potential-code-execution-1' triggered.",
            "check_id": "languages.golang.slack.potential-code-execution-1",
            "location": "test.go",
            "reason": "Test FP",
            "jira": "PRODSEC-XYZ",
            "risk": "Informational",
        }
    }

    revision = setup_test_case(test_name, test_lang, false_positives)
    checkpoint_output = do_scan(test_name, revision["1_pr"], revision["0_master"])

    assert "checkpoint_results.json" in checkpoint_output

    checkpoint_result = json.loads(checkpoint_output["checkpoint_results.json"])

    assert len(checkpoint_result) == 1
    assert checkpoint_result[0]["case"] == "semgrep-scan-non-blocking"
    assert checkpoint_result[0]["level"] == "pass"

    output = json.loads(checkpoint_result[0]["output"])

    assert len(output["comparison"]["results"]) == 0

    assert checkpoint_output["exit_code"] == 0

    take_down_case(test_name, test_lang)


"""
TEST CASES - END
"""
