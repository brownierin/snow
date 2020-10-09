#!/bin/bash

if [ ! -d env ]; then
	python3 -m venv env
fi

source env/bin/activate

# python --version
# python3 --version
# pip --version
# pip3 --version

python3 -m pip install -vvv semgrep --user

repos=`cat enabled`

for repo in $repos; do
	outfile="results-$repo.json"
	git_repo="git@slack-github.com:slack/$repo.git"
	if [ ! -d $repo ]; then
		git clone $git_repo
	fi
	semgrep --config=golang/semgrep.yaml --json -o $WORKSPACE/artifacts/$outfile $repo
done
