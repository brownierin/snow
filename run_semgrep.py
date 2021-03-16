#!/usr/bin/env python3
import subprocess
import configparser
import os
import shutil
import json
import hashlib
import time
import process_hash_ids as comparison

# Get config file and read.
CONFIG = configparser.ConfigParser()
CONFIG.read('config.cfg')

# Global Variables
SNOW_ROOT = os.getenv('PWD')
if CONFIG['general']['run_local_semgrep'] != "False":
    SNOW_ROOT = CONFIG['general']['run_local_semgrep']
LANGUAGES_DIR = SNOW_ROOT + CONFIG['general']['languages_dir']
RESULTS_DIR = SNOW_ROOT + CONFIG['general']['results']
REPOSITORIES_DIR = SNOW_ROOT + CONFIG['general']['repositories']

def cleanup_workspace():
    print('Begin Cleanup Workspace')
    mode = int('775', base=8)
    shutil.rmtree(RESULTS_DIR, ignore_errors=True)
    os.makedirs(RESULTS_DIR, mode=mode, exist_ok=True)
    shutil.rmtree(REPOSITORIES_DIR, ignore_errors=True)
    os.makedirs(REPOSITORIES_DIR, mode=mode, exist_ok=True)
    print('End Cleanup Workspace')

def get_docker_image():
    version = CONFIG['general']['version']
    digest = CONFIG['general']['digest']
    print("Downloading Semgrep")
    subprocess.run(["docker", "pull","returntocorp/semgrep:"+version], check=True, stdout=subprocess.PIPE)
    print("Verifying Semgrep")
    process = subprocess.run("docker inspect --format='{{.RepoDigests}}' returntocorp/semgrep:"+version, shell=True, check=True, stdout=subprocess.PIPE)
    if digest.find((process.stdout).decode("utf-8")) != -1:
        raise Exception("Digest semgrep mismatch!")
    print("Semgrep downloaded and verified")

def download_repos():
    for language in CONFIG.sections():
        git_repo_url = "https://slack-github.com/"
        if language.find('language-') != -1:
            print("Downloading " + str(CONFIG[language]) + " repos")
            filename = LANGUAGES_DIR + CONFIG[language]['language'] + '/enabled'
            with open(filename) as f:
                content = f.read().splitlines()
            for repo in content:
                print("Cloning Repo " + repo)
                git_repo = "git@slack-github.com:slack/" + repo + ".git"
                process = subprocess.run("git -C " + REPOSITORIES_DIR + " clone " + git_repo, shell=True,
                                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                # If we fail to download from Enterprise, try tinyspeck
                if process.returncode == 128:
                    git_repo_url = "https://github.com/tinyspeck"
                    git_repo = "https://github.com/tinyspeck/" + repo + ".git"
                    process = subprocess.run("git -C " + REPOSITORIES_DIR + " clone " + git_repo, shell=True, check=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                print(process.stdout.decode("utf-8"))
                get_sha_process = subprocess.run("git -C " + REPOSITORIES_DIR +"/"+repo +" rev-parse HEAD", shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                git_sha = get_sha_process.stdout.decode("utf-8")
                scan_repo(repo, CONFIG[language]['language'], language, git_repo_url, git_sha)

def scan_repo(repo, language, configlanguage, git_repo_url, git_sha):
    print('Scanning Repo ' + repo)
    output_file = language + "-" + repo + ".json"
    semgrep_command = "docker run --user \"$(id -u):$(id -g)\" --rm -v " + SNOW_ROOT + ":/src returntocorp/semgrep:" + \
                      CONFIG['general']['version'] + " " + CONFIG[configlanguage]['config'] + " " + \
                      CONFIG[configlanguage]['exclude'] + " --json -o /src" + CONFIG['general'][
                          'results'] + output_file + " --error repositories/" + repo + " --dangerously-allow-arbitrary-code-execution-from-rules"
    print(semgrep_command)
    # Purposely do not check shell exit code as vulnerabilities returns a 1
    process = subprocess.run(semgrep_command, shell=True, stdout=subprocess.PIPE)
    # Results here should be sent to a new function for us to work with!
    print(process.stdout.decode("utf-8"))
    # We want to capture where these results came from. GitHub, and Branch in the file
    print("OPENING " + SNOW_ROOT + CONFIG['general']['results'] + output_file)
    # Read The Json Data
    with open(SNOW_ROOT + CONFIG['general']['results'] + output_file, ) as file:
        git_repo_branch = git_sha
        data = json.load(file)
        data.update({"metadata": {"GitHubRepo": git_repo_url, "branch": git_repo_branch, "repoName": repo}})
    # Write to the same file
    with open(SNOW_ROOT + CONFIG['general']['results'] + output_file, 'w') as file:
        json.dump(data, file, sort_keys=True, indent=4)
        file.close()

    # fprm stands for false positives removed
    fp_diff_outfile = f"{language}-{repo}-fprm.json"
    fp_file = f"languages/{language}/{false_positives}/{repo}.json"

    # Add hash identifier to the json result
    # and remove false positives from the output file
    if os.path.exists(RESULTS_DIR+output_file):
        add_hash_id(RESULTS_DIR+output_file)
        comparison.remove_false_positives(
                                            RESULTS_DIR+output_file,
                                            fp_file,
                                            fp_diff_outfile
                                        )


# Grab source codes. Also include one line above and one line below the issue location
def read_line(issue_file, line):    
    with open(issue_file) as f:
        content = f.readlines()
        # check lines
        start = line - 2 if line - 2 > 0 else 0
        end = line + 1 if len(content) >= line + 1 else len(content)
        data = content[start:end]
    return "".join(data).replace("\n", "|")


# Function to add hash field to the semgrep json output as a unique id
# The hash is sha 256 value of : check_id + path + 3 line of codes
# NOTE: We don't hash the line number. Code addition could change the line number
def add_hash_id(jsonFile):
    # Open json file
    f = open(jsonFile, "r")
    data = json.load(f)
    f.close()

    for issue in data["results"]:
        # Check issue metadata
        if (issue["path"] is None) or (issue["start"]["line"] is None):
            continue

        file_path = issue["path"]
        line = issue["start"]["line"]
        base_code = read_line(file_path, line)

        # Check line from out exist in the base_code
        if issue["extra"]["lines"] in base_code:
            base_hash = issue["check_id"] + "|" + file_path + "|" + base_code
        else:
            base_hash = (
                issue["check_id"] + "|" + file_path + "|" + issue["extra"]["lines"]
            )

        # Hash the base
        res = bytes(base_hash, "utf-8")
        hash_digest = hashlib.sha256(res).hexdigest()

        # Update the json blob
        issue["hash_id"] = hash_digest

    ## Save our changes to JSON file
    jsonFile = open(jsonFile, "w+")
    jsonFile.write(json.dumps(data))
    jsonFile.close()

# Alert Channel iterates through the /results directory. Reads the JSON files, and outputs the alerts to SLACK per CONFIG file.
# Alerts utilize the 'slack' command on servers, which allows messages to be sent. Careful with backticks.
# Alerts will not fire unless on a server 'slack'. Command is different on local env.
def alert_channel():
    semgrep_output_files = os.listdir(RESULTS_DIR)
    semgrep_errors = False
    alert_json, error_json = {}, {}
    high, normal, total_vulns = 0, 0, 0
    #Get the high priority config

    high_priority_rules_check_id = CONFIG['high-priority']['high_priority_rules_check_id'].split('\n')
    high_priority_rules_message = CONFIG['high-priority']['high_priority_rules_message'].split('\n')

    # Iterate through the /results file
    for semgrep_output_file in semgrep_output_files:
        print("Reading JSON Output File " + semgrep_output_file)
        # Parse the json file and collect any results present
        with open(RESULTS_DIR + semgrep_output_file) as file:
            data = json.load(file)
            results = data["results"]
            errors = data["errors"]
            repo_name = data["metadata"]["repoName"]
            alert_json.update({repo_name: {"normal": [], "high": []}})
            github_url = data["metadata"]["GitHubRepo"]
            if github_url == "https://slack-github.com/":
                github_url = github_url+"slack/"
            elif github_url == "https://github.com/":
                github_url = github_url + "tinyspeck/"
            github_branch = data["metadata"]["branch"]
            # Check if there are results or errors.
            if results:
                for result in results:
                    check_id = result["check_id"]
                    # path always gives us /repositories/<repo>/dir/filename.py
                    # We do not want /repositories/ or <repo> as this is not valid for a GitHub url
                    code_path = result["path"].split('/', 2)[2:][0]
                    line_start = result["start"]["line"]
                    message = result["extra"]["message"]
                    # Because a single line JavaScript file exists we truncate...
                    code_lines = result["extra"]["lines"][:300]
                    code_url = github_url + repo_name + "/blob/" + github_branch + "/" + code_path + "#L" + str(line_start)
                    priority = "normal"
                    result_builder = "*Security Vulnerability Detected in "+repo_name+"*\n:exclamation:*Rule ID:* " + check_id + "\n:speech_balloon: *Message:* " + message + "\n:link:*Link*: "+code_url+"\n:coding_horror: *Code:*\n\`\`\`" + code_lines + "\`\`\`"
                    total_vulns = total_vulns+1
                    # Check if rule should be treated as a high priority alert.
                    if check_id in high_priority_rules_check_id:
                        high = high+1
                        priority = "high"
                    else:
                        for high_priority_string in high_priority_rules_message:
                            if high_priority_string in message:
                                high = high+1
                                priority = "high"
                    alert_json[repo_name][priority].append(result_builder)
            # If any errors, mark them. This is where we would add additional logic to output errors into a errors_builder.
            # Currently making errors pretty are out scope.
            if errors:
                semgrep_errors = True
                error_json.update({repo_name: errors})
    normal = total_vulns - high
    #########################################################################
    # !!!!!!Subprocess Slack Alerts, Will Only Work On SLACK Servers!!!!!!!!!
    #########################################################################

    # Semgrep Daily Run Banner + vulnerability count of total, high, normal.
    subprocess.run("echo \":snowflake:*Daily :block-s: :block-e: :block-m: :block-g: :block-r: :block-e: :block-p: Scan Report*:snowflake: \n :blob-throw-snow-left:*Rules Triggered*:blob-throw-snow-right:\n---High:"+str(high)+"\n---Normal:"+str(normal)+" \" | slack --channel="+CONFIG['general']['alertchannel']+" --cat --user=SNOW ",shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if total_vulns > 0:
        #Fire High Banner
        subprocess.run("echo \":fire: :fire: :fire: :fire: :fire: :fire:\n:fire::block-h: :block-i: :block-g: :block-h:  :fire:\n:fire: :fire: :fire: :fire: :fire: :fire:\" | slack --channel="+CONFIG['general']['alertchannel']+" --cat --user=SNOW ", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for repo in alert_json:
            for vuln in alert_json[repo]['high']:
                subprocess.run("echo \"" + vuln + "\" | slack --channel="+CONFIG['general']['alertchannel']+" --cat --user=SNOW ", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                time.sleep(1)

        #Snowflake Normal Banner
        subprocess.run("echo \":snowflake::snowflake::snowflake::snowflake::snowflake::snowflake::snowflake::snowflake::snowflake:\n:snowflake: :block-n: :block-o: :block-r: :block-m: :block-a: :block-l: :snowflake:\n:snowflake::snowflake::snowflake::snowflake::snowflake::snowflake::snowflake::snowflake::snowflake: \" | slack --channel="+CONFIG['general']['alertchannel']+" --cat --user=SNOW ",shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for repo in alert_json:
            for vuln in alert_json[repo]['normal']:
                subprocess.run("echo \"" + vuln + "\" | slack --channel="+CONFIG['general']['alertchannel']+" --cat --user=SNOW ", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                time.sleep(1)

    elif not error_json:
        # ALL HAIL THE GLORIOUS NO VULNS BANNER
        text = """:black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square:\n:black_square::sun-turtle::black_square::black_square::black_square::sun-turtle::black_square::black_square::sun-turtle::sun-turtle::black_square::black_square::black_square::black_square::sun-turtle::black_square::black_square::black_square::sun-turtle::black_square::sun-turtle::black_square::black_square::black_square::sun-turtle::black_square::sun-turtle::black_square::black_square::black_square::sun-turtle::black_square::black_square::black_square::sun-turtle::black_square::black_square::sun-turtle::sun-turtle::sun-turtle::black_square:\n:black_square::sun-turtle::sun-turtle::black_square::black_square::sun-turtle::black_square::sun-turtle::black_square::black_square::sun-turtle::black_square::black_square::black_square::sun-turtle::black_square::black_square::black_square::sun-turtle::black_square::sun-turtle::black_square::black_square::black_square::sun-turtle::black_square::sun-turtle::black_square::black_square::black_square::sun-turtle::sun-turtle::black_square::black_square::sun-turtle::black_square::sun-turtle::black_square::black_square::black_square::black_square:\n:black_square::sun-turtle::black_square::sun-turtle::black_square::sun-turtle::black_square::sun-turtle::black_square::black_square::sun-turtle::black_square::black_square::black_square::sun-turtle::black_square::black_square::black_square::sun-turtle::black_square::sun-turtle::black_square::black_square::black_square::sun-turtle::black_square::sun-turtle::black_square::black_square::black_square::sun-turtle::black_square::sun-turtle::black_square::sun-turtle::black_square::black_square::sun-turtle::sun-turtle::black_square::black_square:\n:black_square::sun-turtle::black_square::black_square::sun-turtle::sun-turtle::black_square::sun-turtle::black_square::black_square::sun-turtle::black_square::black_square::black_square::black_square::sun-turtle::black_square::sun-turtle::black_square::black_square::sun-turtle::black_square::black_square::black_square::sun-turtle::black_square::sun-turtle::black_square::black_square::black_square::sun-turtle::black_square::black_square::sun-turtle::sun-turtle::black_square::black_square::black_square::black_square::sun-turtle::black_square:\n:black_square::sun-turtle::black_square::black_square::black_square::sun-turtle::black_square::black_square::sun-turtle::sun-turtle::black_square::black_square::black_square::black_square::black_square::black_square::sun-turtle::black_square::black_square::black_square::black_square::sun-turtle::sun-turtle::sun-turtle::black_square::black_square::sun-turtle::sun-turtle::sun-turtle::black_square::sun-turtle::black_square::black_square::black_square::sun-turtle::black_square::sun-turtle::sun-turtle::sun-turtle::black_square::black_square:\n:black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square::black_square:"""
        subprocess.run("echo \"" + text + "\" | slack --channel="+CONFIG['general']['alertchannel']+" --cat --user=SNOW ", shell=True,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if semgrep_errors:
        # Right now I am purposely not outputting errors. There are a lot and its noise. To Do: Make a pretty output once cleaned.
        subprocess.run("echo \":test-error: There were errors this run. Check Jenkins https://jenkins.tinyspeck.com/job/security-semgrep-prodsec \" | slack --channel="+CONFIG['general']['alertchannel']+" --cat --user=SNOW ",
            shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def compare_runs():
    for file in RESULTS_DIR:
        process_hash_ids.compare(inputold, inputnew, output)


if __name__ == '__main__':
    # Delete all directories that would have old repos, or results from the last run as the build boxes may persist from previous runs.
    cleanup_workspace()
    # Get Semgrep Docker image, check against a known good hash
    get_docker_image()
    # Download the repos in the language enabled list and run
    download_repos()
    # Output Alerts to channel
    alert_channel()
    compare_runs()
