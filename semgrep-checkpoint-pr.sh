#! /bin/bash

#Purpose of this script is to run the Global Checkpoint test for Semgrep PRs. 
#This test resides within SNOW but is kicked off from Checkpoint here...
#https://slack-github.com/slack/checkpoint/blob/master/src/config/ProdConf.hack

#Use the CIBOT_REPO to retrive the repo name. IE from: https://slack-github.com/tfaraci/rains.git
REPO_NAME=`echo $CIBOT_REPO | awk -F[/.] '{print tolower($6)}'`

# If in staging, grab, change the awk grab for the repo. 
SUB='staging.slack-github'
if [[ "$CIBOT_REPO" == *"$SUB"* ]]; then
  REPO_NAME=`echo $CIBOT_REPO | awk -F[/.] '{print tolower($7)}'`
fi

echo CIBOT_REPO $CIBOT_REPO
echo REPO_NAME $REPO_NAME

cd $WORKSPACE

echo Temp rm for old dirs
rm -rf $WORKSPACE/$REPO_NAME
rm -rf $WORKSPACE/checkout/snow

rm -rf repos/snow/repositories/$REPO_NAME
mkdir -p repos/snow/repositories/$REPO_NAME
cp -a checkout/. repos/snow/repositories/$REPO_NAME/

#SNOW should already be downloaded per the slack.json configuration in the global test.
#Script needs to be run in the SNOW dir
cd $WORKSPACE/repos/snow


#Run pre-install.sh as we need f-strings to work
#cmd output is in pre-install.log
./pre-install.sh > pre-install.log 2>&1

#Run semgrep in PR mode. -m Mode, -r Repo, -g GitHub Instance. 
echo ./run_semgrep.py -m pr -r $REPO_NAME -g ghe
./run_semgrep.py -m pr -r $REPO_NAME -g ghe
