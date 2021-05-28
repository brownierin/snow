# Manual triage

This document shows how to :

 * Obtain all the findings of the projects you want.
 * Triage the findings.
 * Add the false positives you found in the `_false_positives.json` files.

## Obtaining the list of all the findings

If you do not wish to scan all the projects, make sure that only the project you want to scan are present in the `enabled` file for each language.

Run the semgrep scan with the `daily` mode.

≥ ./run_semgrep.py -m daily

Once the scan is completed, the results will be generated as JSON files in the `results/` folder. To convert these JSON file to a more usable format, you can use the existing conversion script. Do note that multiple JSON file are generated with the scan and that you usually only want to use the ones that end with `-fprm.json` as they contain the `hash_id` field and they don't contain the findings that are marked as false positive.

≥ ./json_results_to_csv.py -o combined.csv results/*-fprm.json

## Triage the findings

You must first import the generated CSV in the tool of your choice (Google Sheets, Excel, etc.). Once this is done, the triaging is done by looking at the information listed on every line and filling the following columns :

 * Status : This column indicate whether the finding is a false positive "FP" or a true positive "TP". Value should be "FP" or "TP".
 * Notes : If you marked a finding as a false positive, make sure to document why it is a false positive in this column.

The other blank columns are generated for cosmetic/utility reason and aren't used in other scripts. Use them if you find them useful for tracking.

## Generating the false positive files

Once you are done triaging the findings, export your sheet as CSV. Then use the following scripts to add the false positives information to the existing false positives files.

≥ ./generate_false_positives_files.py -f your_file.csv

Make sure to commit and push the changes made to the false positives files.