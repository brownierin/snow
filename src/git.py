import sys


from src.config import *
from src.util import *
from src.exceptions import *
from src.repos import *
import src.slack as slack
import src.webhooks as webhooks
import src.comparison as comparison


def download_repos():
    """
    Download all repos listed in the enabled files
    """
    repos = get_repo_list()
    for repo in repos:
        git_ops(repo)
    get_default_branches(repos)


def force_redownload(repo_path):
    repo = repo_path.split("/")[-1]
    try:
        rm_dir(repo_path)
        git_ops(repo)
    except Exception as e:
        logging.exception(e)
    else:
        return True


def git_ops(repo):
    url, org, repo = repo.split("/")
    set_ssh_key(url)
    repo_path = f"{REPOSITORIES_DIR}{repo}"
    git_repo = f"git@{url}:{org}/{repo}.git"

    if slack.is_webapp(repo):
        slack.slack_repo(repo, git_repo, repo_path, REPOSITORIES_DIR)
    elif os.path.isdir(f"{repo_path}"):
        logging.info(f"Updating repo: {repo}")
        git_pull_repo(repo_path)
    else:
        logging.info(f"Cloning {repo}")
        clone_command = f"git -C {REPOSITORIES_DIR} clone {git_repo}"
        clone = run_command(clone_command)

        # Git repositories that are pulled from github.com are marked as unsafe and as such
        # subsequent git command may fail with error saying that the repository is untrusted.
        # This small fixes ensures that all the commands work on those repositories. We only
        # need to do this once after the repository is cloned.
        if url == ghc_url:
            trust_this_repo_command = f"git config --global --add safe.directory {repo_path}"
            run_command(trust_this_repo_command)


def git_pull_repo(repo_path):
    """
    When "git pull" fails it's sometimes because there was a
    force push done at some point to the repo.
    In this case the pull fails because we have local commits
    that don't exists in the remote.
    We attempt to fix this problem by rebasing the local repo
    with the main branch of the remote.
    A pull can also fail if we're in a headless state. The
    checkout below fixes this.
    """
    symref_process = run_command(f"git -C {repo_path} remote show origin | sed -n '/HEAD branch/s/.*: //p'")
    default_branch = symref_process.stdout.decode("utf-8")
    try:
        pull(repo_path, default_branch) or reset(repo_path, default_branch) or force_redownload(repo_path)
    except Exception as e:
        raise e


def pull(repo_path, default_branch):
    try:
        run_command(f"git -C {repo_path} checkout {default_branch}")
        cmd = run_command(f"git -C {repo_path} pull")
        logging.info({cmd.stdout.decode("utf-8")})
    except Exception as e:
        logging.exception(e)
    else:
        return True


def reset(repo_path, default_branch):
    try:
        run_command(f"git -C {repo_path} reset --hard origin/{default_branch}")
        run_command(f"git -C {repo_path} pull")
    except Exception as e:
        logging.exception(e)
    else:
        return True


def git_merge_base(repo_path, git_sha, remote_master_name):
    cmd = f"git -C {repo_path} merge-base {git_sha} forked/{remote_master_name}"
    try:
        merge_base_process = run_command(cmd)
        forked_commit_id = merge_base_process.stdout.decode("utf-8").strip()
    except subprocess.CalledProcessError:
        raise GitMergeBaseError
    else:
        logging.info(f"Using the commit id {forked_commit_id} as the commit the repo is forked from.")
        return forked_commit_id


def git_forked_repos(repo_long, language, git_sha):
    repo = repo_long.split("/")[2]
    repo_path = f"{REPOSITORIES_DIR}{repo}"
    repo_language = language.replace("language-", "")

    # Setup the upstream repo as a remote
    forked_repo = FORKED_REPOS[repo]
    logging.info(f"Repository is forked from {forked_repo}.")

    # fetch the upstream repo
    command = f"git -C {repo_path} remote | grep -q '^forked$' || git -C {repo_path} remote add forked {forked_repo}"
    run_command(command)
    run_command(f"git -C {repo_path} fetch forked")

    # Get the remote "master" branch name (not always "master")
    cmd = f"git -C {repo_path} remote show forked | sed -n '/HEAD branch/s/.*: //p'"
    symref_process = run_command(cmd)
    remote_master_name = symref_process.stdout.decode("utf-8")

    # Identify the commit id it was forked from
    try:
        forked_commit_id = git_merge_base(repo_path, git_sha, remote_master_name)
    except GitMergeBaseError as e:
        message = f"Skipping scanning fork of {repo}. git merge_base failed. {e.message}"
        logging.error(message)
        webhooks.send(f"*Error*: {message}")
        return

    """
    In this special case, we haven't pushed any custom code into the forked 
    repo as the HEAD of the repo exists in the repo we forked it from.
    Note: startswith is used in case the git_sha is a shortened commit hash.
    """
    if forked_commit_id.startswith(git_sha):
        logging.info(
            "We have detected that this repository doesn't contain any custom commits. "
            "Returning no findings because of this."
        )
        for suffix in ["", "-fprm"]:
            output = f"{RESULTS_DIR}{repo_language}-{repo}-{forked_commit_id[:7]}{suffix}.json"
            # This will remove all the entries in the results but keeps the metadata about the scan.
            # While this is odd code, it will ensure the output is consistent with other scan results.
            if os.path.exists(output):
                comparison.compare_to_last_run(output, output, output)
        return

    # scan_repo(repo_long, language, forked_commit_id)

    # Compare the results and overwrite the original result with the comparison result
    for suffix in ["", "-fprm"]:
        file_prefix = f"{RESULTS_DIR}{repo_language}-{repo}-"
        forked_output = f"{forked_commit_id[:7]}{suffix}.json"
        new_output = f"{file_prefix}{git_sha[:7]}{suffix}.json"

        if os.path.exists(forked_output):
            comparison.compare_to_last_run(forked_output, new_output, new_output)
   

def get_default_branches(repolist):
    defaults = {repo: {"default_branch": default_branch(repo), "git_sha": rev_parse_head(repo)} for repo in repolist}
    filepath = f"{RESULTS_DIR}repo_info.json"
    with open(filepath, "w") as file:
        json.dump(defaults, file, sort_keys=True, indent=4)
    return defaults


def default_branch(repo):
    repo_path = f"{REPOSITORIES_DIR}{repo}"
    cmd = f"git -C {repo_path} remote show origin | grep 'HEAD branch' | sed 's/.*: //'"
    return run_command(cmd).stdout.decode("utf-8").strip()


def rev_parse_head(repo):
    git_sha_process = run_command(f"git -C {REPOSITORIES_DIR}{repo} rev-parse HEAD")
    return git_sha_process.stdout.decode("utf-8").rstrip()


def get_master_commit_id(repo_dir):
    git_dir = f"git -C {repo_dir}"
    run_command(f"{git_dir} branch --list --remote origin/master")
    if os.environ.get(master_commit_env):
        master_sha = os.environ.get(master_commit_env)
    else:
        cmd = f"{git_dir} show -s --format='%H' origin/master"
        master_sha = run_command(cmd).stdout.decode("utf-8").strip()
    return master_sha


def get_branch_commit_id(url):
    # Uses the branch commit id env var in both github actions and checkpoint
    slack.commit_head(url)
    branch_sha = os.environ.get(commit_head_env)
    return branch_sha


def merge(repo_dir, master_sha):
    # Make sure we are scanning what the repo would look like after a merge
    # This prevents issues where a vulnerability is removed in master and the
    # scan wronly believes that it's introduced by the PR branch because the PR
    # branch is based on a commit that was before the vulnerability was removed.
    git_dir = f"git -C {repo_dir}"   
    process = run_command(f"{git_dir} merge {master_sha}")
    logging.info(f"Ran a merge. Output: {process.stdout.decode('utf-8').strip()}")


def git_ops_pr_scan(repo_long):
    repo_long = remove_scheme_from_url(repo_long)
    url, org, repo = repo_long.split("/")
    repo_dir = f"{REPOSITORIES_DIR}{repo}"
    
    branch_sha = get_branch_commit_id(url)
    master_sha = get_master_commit_id(repo_dir)

    if branch_sha == master_sha:
        logging.error("Master and HEAD are equal. Need to compare against two different SHAs! We won't scan.")
        sys.exit(0)

    repo_info = {"repo": repo, "branch_sha": branch_sha, "master_sha": master_sha}

    with open(f"{RESULTS_DIR}repo_info.json", "w") as file:
        json.dump(repo_info, file, sort_keys=True, indent=4)

    merge(repo_dir, master_sha)


def get_commit_id_at_date(date, repo):
    # Date format should be 2022-09-14
    repodir = f"{REPOSITORIES_DIR}{repo}"
    cmd = run_command(f"""git -C {repodir} log --before={date} -1 --pretty=format:"%H" """)
    return cmd.stdout.decode("utf-8")
