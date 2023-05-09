#!/usr/bin/python3
from run_semgrep import get_repo_list, trim_repo_list
from src.util import run_command

repos_full = get_repo_list()
repos = trim_repo_list(repos_full)


def basename(path):
    return path.split("/")[-1]


for repo in repos:
    repo_path = f"repositories/{repo}"
    files = run_command(f"git -C {repo_path} ls-files")
    files = files.stdout.decode("ascii")
    files = files.split("\n")

    prepended_files = [f"{repo_path}/{file}" for file in files]

    with open(f"{repo}.txt", "w") as outfile:
        for fname in prepended_files:
            if not basename(fname).startswith("."):
                if basename(fname) != "":
                    try:
                        with open(fname) as infile:
                            for line in infile:
                                outfile.write(line)
                    except UnicodeDecodeError as e:
                        # print(e)
                        # print(fname)
                        continue
                    except:
                        continue
    lines = run_command(f"cat {repo}.txt | wc -l")

    with open("count.txt", "a+") as outfile:
        text = f"{repo},{lines.stdout.decode('ascii')}"
        print(text)
        outfile.write(text)
