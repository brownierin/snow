import os
import glob
import json

SNOW_ROOT = os.path.realpath(os.path.dirname(os.path.realpath(__file__)) + "/../../")

# Checks that all false positive file are valid
def test_valid_false_positives_file():
    all_fp_files = list(glob.glob(f"{SNOW_ROOT}/languages/*/false_positives/*_false_positives.json"))

    assert len(all_fp_files) > 0

    for file in all_fp_files:
        with open(file, "r") as f:
            data = json.load(f)
            assert isinstance(data, dict)
