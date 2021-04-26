#! /bin/bash

set +x

webapp_repo=$WORKSPACE/snow/repositories/webapp/

if [ ! -d webapp_repo ]
then
	cp -R /mnt/persist/https___slack_github_com_slack_webapp webapp_repo
fi

git -C $WORKSPACE/snow/repositories/webapp fetch --tags --force --progress -- git@slack-github.com:slack/webapp +refs/heads/*:refs/remotes/origin1/* 

