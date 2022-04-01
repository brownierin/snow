#!/usr/bin/bash

# This script sets up the required values
# for a local run of the PR scan
# from Github Actions

export PWDTLD=$(pwd)
cd repositories
rm -rf fake_repo
git clone git@github.com:slackhq/fake_repo.git
cd $PWDTLD

export BRANCH_NAME=$(git -C repositories/fake_repo branch --show-current)
export GITHUB_SHA=$(git -C repositories/fake_repo rev-parse refs/heads/$BRANCH_NAME)
echo "Branch SHA is:" $GITHUB_SHA
