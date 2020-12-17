#!/bin/bash

version=0.34.0
digest="95d7e8ad79e140552331443aa473b56d6d06e8d878077d9039c36407de184427"
docker pull returntocorp/semgrep:$version
docker inspect --format='{{.RepoDigests}}' returntocorp/semgrep:$version | grep -qF $digest

if [ $? -eq 1 ]; then
	echo "[!!] Error: Docker image digests don't match"
	exit 1
fi

LANGUAGE=$2
results="results"

 scanLanguage() {
  language=$1
  repos=$2
  for repo in $repos; do
    outfile="results-$language-$repo.json"
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
			--config=/src/languages/$language/semgrep.yaml --json -o /src/$results/$outfile --error repositories/$repo
		code=$?
		exit_codes+=$code
		exit_codes+=' '
	done
 }


function run_semgrep {
	set -x
	echo "[+] Clearing results from previous run"
	exit_codes=()
	rm -rf $WORKSPACE/snow/$results
	mkdir $WORKSPACE/snow/$results
	chmod o+w $WORKSPACE/snow/$results
	mkdir -p repositories

  if [ $LANGUAGE == "golang" ]; then
     repos=`cat $WORKSPACE/snow/languages/golang/enabled`
     scanLanguage "golang" $repos
  elif [ $LANGUAGE  == "javascript" ]; then
      repos=`cat $WORKSPACE/snow/languages/javascript/enabled`
      scanLanguage "javascript" $repos
  elif [ $LANGUAGE  == "typescript" ]; then
      repos=`cat $WORKSPACE/snow/languages/typescript/enabled`
  elif [ $LANGUAGE  == "java" ]; then
      repos=`cat $WORKSPACE/snow/languages/java/enabled`
  fi

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
