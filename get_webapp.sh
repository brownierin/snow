#! /bin/bash

set +x

webapp_repo=$WORKSPACE/snow/repositories/webapp/
webapp_url=git@slack-github.com:slack/webapp
ref=/mnt/persist/https___slack_github_com_slack_webapp

if [ ! -d webapp_repo ]
then
    echo "[+] clone webapp from reference"
    git -C $WORKSPACE/snow/repositories clone --reference $ref $webapp_url
fi

echo "[+] fetch updates to webapp"
git -C $webapp_repo fetch --tags --force --progress -- $webapp_url +refs/heads/*:refs/remotes/origin1/*
