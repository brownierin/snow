#!/usr/bin/env python3

import pprint
import subprocess
import configparser
import os
import glob
import json

CONFIG = configparser.ConfigParser()
CONFIG.read('config.cfg')

SNOW_ROOT = os.getenv('PWD')

def scan_folder(folder, configlanguage, output_file):
    semgrep_command = "docker run --user \"$(id -u):$(id -g)\" --rm " + \
        "-v " + SNOW_ROOT + ":/src " + \
        "returntocorp/semgrep:" + CONFIG['general']['version'] + " " + \
        CONFIG[configlanguage]['config'] + " " + \
        CONFIG[configlanguage]['exclude'] + \
        " --json" + \
        " -o /src" + CONFIG['general']['results'] + output_file + \
        " --error " + \
        CONFIG['general']['tests_repositories'][1:] + folder + \
        " --dangerously-allow-arbitrary-code-execution-from-rules"

    subprocess.run(semgrep_command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

local_test_directory = SNOW_ROOT + CONFIG['general']['tests_repositories']
local_results_directory = SNOW_ROOT + CONFIG['general']['results']

is_all_test_success = True
test_ran = 0
test_ran_success = 0
test_ran_fail = 0

for test_config_path in glob.glob(local_test_directory + "/*/*/test.json"):
    try:
        file_part = test_config_path.split("/")
        test_case_name = file_part[-2]
        language = file_part[-3]

        test_config = {}
        with open(test_config_path) as f:
            test_config = json.load(f)

        output_file = "test-%s-%s.json" % (language, test_case_name)
        language_config = "language-%s" % (language)
        relative_path = "%s/%s" % (language, test_case_name)

        scan_folder(relative_path, language_config, output_file)

        scan_result = {}
        with open(local_results_directory + output_file) as f:
            scan_result = json.load(f)

        # We start by assuming that the test case is a success
        is_success = True

        # Check if this outputs the correct amount of finding
        result_count = len(scan_result["results"])
        expected_count = test_config["expected-result-count"]
        if not result_count == expected_count:
            print("[ERR] Expected %d results from test case '%s', but got %d." % (expected_count, test_case_name, result_count))
            is_success = False

        # Check if the correct rule got triggered
        expected_rule_match = test_config["expected-match"]
        found_rule = []
        for item in scan_result["results"]:
            if not item["check_id"] in expected_rule_match:
                print("[ERR] Test returned an unexpected rule match '%s'." % (item["check_id"]))
                is_success = False
            else:
                found_rule.append(item["check_id"])

        # Check if all the rule got matched
        for rule in expected_rule_match:
            if not rule in found_rule:
                print("[ERR] The rule '%s' was not matched." % (rule))
                is_success = False

    except Exception as e:
        print("[ERR] An unexpected error occured while running the test case '%s' (%s)." % (test_case_name, str(e)))
        is_success = False

    test_ran += 1
    if is_success:
        print("[OK] %s" % (test_case_name))
        test_ran_success += 1
    else:
        is_all_test_success = False
        test_ran_fail += 1

print("[INFO] %d test executed. Passed :  %d Fail : %d." % (test_ran, test_ran_success, test_ran_fail))

if is_all_test_success:
    print("[OK] All test passed !")
else:
    print("[ERR] Some test fail. See the logs for more information.")
