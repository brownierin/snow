#!/usr/bin/env python3
import subprocess
import configparser
import os
import shutil

# Get config file and read.
CONFIG = configparser.ConfigParser()
CONFIG.read('config.cfg')

# Global Variables
WORKSPACE = os.getenv('WORKSPACE')
if CONFIG['general']['run_local_semgrep'] != "False":
    WORKSPACE = CONFIG['general']['run_local_semgrep']
SNOW_ROOT = WORKSPACE + CONFIG['general']['snow_root']
LANGUAGES_DIR = SNOW_ROOT + CONFIG['general']['languages_dir']
RESULTS_DIR = SNOW_ROOT + CONFIG['general']['results']
REPOSITORIES_DIR = SNOW_ROOT + CONFIG['general']['repositories']

def cleanup_workspace():
    mode = int('774', base=8)
    shutil.rmtree(RESULTS_DIR, ignore_errors=True)
    os.makedirs(RESULTS_DIR, mode=mode, exist_ok=True)
    shutil.rmtree(REPOSITORIES_DIR, ignore_errors=True)
    os.makedirs(REPOSITORIES_DIR, mode=mode, exist_ok=True)

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
        if language.find('language-') != -1:
            print("Downloading "+str(CONFIG[language])+" repos")
            filename = LANGUAGES_DIR+CONFIG[language]['language']+'/enabled'
            with open(filename) as f:
                content = f.read().splitlines()
            for repo in content:
                print("Cloning Repo "+repo)
                git_repo = "git@slack-github.com:slack/"+repo+".git "
                subprocess.run("git -C "+REPOSITORIES_DIR+" clone --quiet "+git_repo, shell=True, check=True, stdout=subprocess.PIPE)
                scan_repo(repo,CONFIG[language]['language'])

def scan_repo(repo, language):
    print('Scanning Repo '+repo)
    config_dir = "/src/languages/"+language
    output_file = language+"-"+repo+".json"
    print("docker run --rm -v "+SNOW_ROOT+":/src returntocorp/semgrep:"+CONFIG['general']['version'] + " --config="+config_dir+" --json -o /src" + CONFIG['general']['results']+output_file + " --error repositories/"+repo)
    #Purposely do not check shell exit code as vulnerabilities returns a 1
    process = subprocess.run("docker run --rm -v "+SNOW_ROOT+":/src returntocorp/semgrep:"+CONFIG['general']['version'] + " --config="+config_dir+" --json -o /src" + CONFIG['general']['results']+output_file + " --error repositories/"+repo, shell=True, stdout=subprocess.PIPE)
    #Results here should be sent toa new function for us to work with!
    print(process.stdout.decode("utf-8"))

if __name__ == '__main__':
    # Delete all directories that would have old repos, or results from the last run as the build boxes may persist from previous runs.
    cleanup_workspace()
    # Get Semgrep Docker image, check against a known good hash
    get_docker_image()
    #Download the repos in the language enabled list and run
    download_repos()
