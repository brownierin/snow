#!/bin/bash

version=0.27.0
digest="8ed62d34b6149f9d08fcce55b27d21f850e3a87e21f10aeb5bfb00e0a0faa0ef"
docker pull returntocorp/semgrep:$version
docker inspect --format='{{.RepoDigests}}' returntocorp/semgrep:$version | grep -qF $digest

if [ $? -eq 1 ]; then
	echo "[!!] Error: Docker image digests don't match"
	exit 1
fi

results="results"

function run_semgrep {
	set -xe
	echo "[+] Clearing results from previous run"
	rm -rf $WORKSPACE/snow/$results
	mkdir $WORKSPACE/snow/$results
	chmod o+w $WORKSPACE/snow/$results

	repos=`cat $WORKSPACE/snow/enabled`

	for repo in $repos; do
		outfile="results-$repo.json"
		git_repo="git@slack-github.com:slack/$repo.git"
		if [ ! -d $repo ]; then
			git clone --quiet $git_repo
		fi
		docker run --rm -v "${WORKSPACE}/snow:/src" \
			returntocorp/semgrep:0.27.0 \
			--config=/src/golang/semgrep.yaml --json -o /src/$results/$outfile --error $repo
	done

	set +xe
	status=$? 
	exit $status
}

function run_semgrep_locally {
	# for local dev, set WORKSPACE to be one dir above your SNOW repo
	echo "[!!] Set WORKSPACE before running!"
	export WORKSPACE=~/src
	echo "[+] WORKSPACE is set to ${WORKSPACE}"
	run_semgrep
}

CMD=$1
if [ "$CMD" == "run_semgrep" ]; then
    run_semgrep
elif [ "$CMD" == "run_semgrep_locally" ]; then
	run_semgrep_locally
fi
