#!/usr/bin/env python3

import sys, os

SNOW_ROOT = os.path.realpath(os.path.dirname(os.path.realpath(__file__)) + "/../../")
sys.path.append(SNOW_ROOT)

import subprocess
import configparser
import glob
import json
import argparse
from concurrent.futures import ThreadPoolExecutor
from checkpoint_out import create_checkpoint_results_json

CONFIG = configparser.ConfigParser()
CONFIG.read('config.cfg')

def scan_folder(folder, configlanguage, output_file):
    semgrep_command =  "docker run --user \"$(id -u):$(id -g)\" --rm "
    semgrep_command += "-v " + SNOW_ROOT + ":/src "
    semgrep_command += "returntocorp/semgrep:" + CONFIG['general']['version'] + " "
    semgrep_command += CONFIG[configlanguage]['config'] + " "
    semgrep_command += CONFIG[configlanguage]['exclude']
    semgrep_command += " --json"
    semgrep_command += " -o /src" + CONFIG['general']['results'] + output_file
    semgrep_command += " --error "
    semgrep_command += CONFIG['general']['tests_repositories'][1:] + folder
    semgrep_command += " --dangerously-allow-arbitrary-code-execution-from-rules"

    subprocess.run(semgrep_command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def do_test(test_case_name, language, test_config_path):
    try:
        test_config = {}
        with open(test_config_path) as f:
            test_config = json.load(f)

        output_file = "test-{}-{}.json".format(language, test_case_name)
        language_config = "language-{}".format(language)
        relative_path = "rules/{}/{}".format(language, test_case_name)

        scan_folder(relative_path, language_config, output_file)

        with open(local_results_directory + output_file) as f:
            scan_result = json.load(f)

        # We start by assuming that the test case is a success
        is_success = True

        # Check if this outputs the correct amount of finding
        result_count = len(scan_result["results"])
        expected_count = test_config["expected-result-count"]
        if not result_count == expected_count:
            print("[WARN] Expected {} results from test case '{}', but got {}.".format(expected_count, test_case_name, result_count))

        # Check if the correct rule got triggered
        expected_rule_match = test_config["expected-match"]
        found_rule = []
        for item in scan_result["results"]:
            if not item["check_id"] in expected_rule_match:
                print("[ERR] Test returned an unexpected rule match '{}'.".format(item["check_id"]))
                is_success = False
            else:
                found_rule.append(item["check_id"])

        # Check if all the rule got matched
        for rule in expected_rule_match:
            if not rule in found_rule:
                print("[ERR] The rule '{}' was not matched.".format(rule))
                is_success = False

    except Exception as e:
        print("[ERR] An unexpected error occured while running the test case '{}' ({}).".format(test_case_name, str(e)))
        is_success = False

    return is_success

parser = argparse.ArgumentParser(description='Test runner for the semgrep rules.')
parser.add_argument('--lang', required=False)
parser.add_argument('--test', required=False)
parser.add_argument('--worker', default=1, required=False)
parser.add_argument('--generate_checkpoint_artifact', default=False, dest='generate_checkpoint_artifact', action='store_true', required=False)
args = parser.parse_args()

local_test_directory = SNOW_ROOT + CONFIG['general']['tests_repositories']
local_results_directory = SNOW_ROOT + CONFIG['general']['results']

is_all_test_success = True
test_ran, test_ran_success, test_ran_fail = 0, 0, 0
test_results = []
pending_test_results = []

with ThreadPoolExecutor(max_workers=int(args.worker)) as executor:
    for test_config_path in glob.glob(local_test_directory + "/rules/*/*/test.json"):
        file_part = test_config_path.split("/")
        test_case_name = file_part[-2]
        language = file_part[-3]

        # Ignore test cases we don't want to run
        if args.lang and not args.lang == language:
            continue

        if args.test and not args.test == test_case_name:
            continue

        future = executor.submit(do_test, test_case_name, language, test_config_path)
        pending_test_results.append({ "future" : future, "test_case_name" : test_case_name })

for result in pending_test_results:
    test_ran += 1
    is_success = result["future"].result()

    if is_success:
        print("[OK] %s" % (result["test_case_name"]))
        test_ran_success += 1
        test_results.append({
            "level" : "pass",
            "case" : "semgrep-rule-" + result["test_case_name"],
            "output" : ""
        })
    else:
        is_all_test_success = False
        test_ran_fail += 1
        test_results.append({
            "level" : "failure",
            "case" : "semgrep-rule-" + result["test_case_name"],
            "output" : ""
        })        

print("[INFO] {} test executed. Passed :  {} Fail : {}.".format(test_ran, test_ran_success, test_ran_fail))

if args.generate_checkpoint_artifact:
    create_checkpoint_results_json(test_results)

if is_all_test_success:
    print("[OK] All test passed !")
else:
    print("[ERR] Some test failed. See the logs for more information.")
    sys.exit(1)
