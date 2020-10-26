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
	set -x
	echo "[+] Clearing results from previous run"
	rm -rf $WORKSPACE/snow/$results
	mkdir $WORKSPACE/snow/$results
	chmod o+w $WORKSPACE/snow/$results

	repos=`cat $WORKSPACE/snow/enabled`
	exit_codes=()
	mkdir -p repositories

	for repo in $repos; do
		outfile="results-$repo.json"
		git_repo="git@slack-github.com:slack/$repo.git"
		cd repositories
		if [ ! -d $repo ]; then
			git clone --quiet $git_repo
		else
			cd $repo
			git pull --no-rebase
			cd ..
		fi
		cd $WORKSPACE/snow
		docker run --rm -v "${WORKSPACE}/snow:/src" \
			returntocorp/semgrep:0.27.0 \
			--config=/src/golang/semgrep.yaml --json -o /src/$results/$outfile --error repositories/$repo
		code=$?
		exit_codes+=$code
		exit_codes+=' '
	done

	set +x
	echo "[+] Exit codes for each semgrep run are: $exit_codes"

	for code in $exit_codes; do
		if [ $code -ne 0 ]; then
			exit $code
		fi
	done
}

function run_semgrep_locally {
	#Set WORKSPACE to be one dir above your SNOW repo!
	echo "[!!] Run this script from your SNOW repo!"
	export WORKSPACE="$(dirname `pwd`)"
	echo "[+] WORKSPACE is set to ${WORKSPACE}"
	run_semgrep
}

CMD=$1
if [ "$CMD" == "run_semgrep" ]; then
    run_semgrep
elif [ "$CMD" == "run_semgrep_locally" ]; then
	run_semgrep_locally
fi
