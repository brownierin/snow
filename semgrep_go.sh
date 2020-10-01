#!/bin/bash

python -m pip3 install semgrep

repos=`cat enabled`

for repo in $repos
do
	outfile="results-$repo.json"
	git_repo="git@slack-github.com:slack/$repo.git"
	git clone $git_repo
	semgrep --config=golang/semgrep.yaml --json -o artifacts/$outfile $repo
done
