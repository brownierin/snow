# How to run ?

To run the tests, move to the root of the SNOW project and run the following command.

> ./run_tests.py

# How to add a test ?

The tests are structured in the following way : 

 - Each test case is in a folder that follows this naming convention : `tests/{languageName}/{testCaseName}/`. 
 - Inside each test case folder we have the following items :
    - `test.json` - Contains the information about this test case.
    - `src/` - Folder that contains the source code to test with the existing rule.
 - The `test.json` has the following properties :
    - `expected-result-count` - The number of expected detected vulnerability.
    - `expected-match` - An array of the expected rule that should be triggered.

Note: If the rule you are adding is intended not to trigger in some cases, it's highly recommended that your test case includes code that shouldn't trigger.

