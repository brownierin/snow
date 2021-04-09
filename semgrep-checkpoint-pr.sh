#! /bin/bash

#Purpose of this script is to run the Global Checkpoint test for Semgrep PRs. 
#This test resides within SNOW but is kicked off from Checkpoint here...
#https://slack-github.com/slack/checkpoint/blob/master/src/config/ProdConf.hack

#Cleanup old version of SNOW
rm -rf ./snow

#Use the CIBOT_REPO to retrive the repo name. IE from: https://slack-github.com/tfaraci/rains.git
REPO_NAME=`echo $CIBOT_REPO | awk -F[/.] '{print tolower($6)}'`

# If in staging, grab, change the awk grab for the repo. 
SUB='staging.slack-github'
if [[ "$CIBOT_REPO" == *"$SUB"* ]]; then
  REPO_NAME=`echo $CIBOT_REPO | awk -F[/.] '{print tolower($7)}'`
fi

#Move the SNOW directory to the repo root, as this is required for SNOW to run. 
#SNOW should already be downloaded per the slack.json configuration in the global test. 
mv ../repos/snow/ .

#Script needs to be run in the SNOW dir
cd snow

#Run semgrep in PR mode. -m Mode, -r Repo, -g GitHub Instance. 
echo ./run_semgrep.py -m pr -r $REPO_NAME -g ghe
./run_semgrep.py -m pr -r $REPO_NAME -g ghe
