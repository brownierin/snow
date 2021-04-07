# SNOW (Static aNalysis nOn Webapp)

This repo is the home of static code analysis tooling for repositories that are not covered by Slack's current SCA tooling for webapp, iOS, and Android repos.

## Description

Under the hood, SNOW uses a fabulous open source tool called [semgrep](https://github.com/returntocorp/semgrep).  Semgrep looks for known potentially insecure code patterns like using `exec()` in PHP, or use of insecure hashing algorithms such as MD5 or SHA1.  Static code analysis is an imperfect process that will sometimes flag false positives, and other times will miss insecure code that doesn't exactly match known patterns.  If this scan returns findings that are invalid, the prodsec team is happy to fine-tune any rules that are consistently faulty, or add new rules at any time, so please let us know if you have ideas by pinging #triage-prodsec.

### Dependencies

* Make sure you have the most recent verison of Docker installed on your machine if you would like to run this program locally.

### Executing program

* Clone this repository to your local machine
* Run semgrep locally by modifying the config.cfg, 'run_local_semgrep' to your desired workspace. 
* Semgrep will run against any language in the config file with the syntax <language-xxxx>. The language directory is determined by 'language' variable. 

```
./run_semgrep.py
```

After running the semgrep script, you should receive an output of JSON to your terminal with a list of rule violations similar to this:

```
{"results": [{"check_id": "languages.php.r2c-rules.file-inclusion", "path": "repositories/rss-parser/test/ParserServiceTest.php", "start": {"line": 4, "col": 1}, "end": {"line": 4, "col": 55}, "extra": {"message": "Non-constant file inclusion. This can lead to LFI or RFI if user\ninput reaches this statement.\n", "metavars": {"$FUNC": {"start": {"line": 4, "col": 1, "offset": 32}, "end": {"line": 4, "col": 8, "offset": 39}, "abstract_content": "require", "unique_id": {"type": "AST", "md5sum": "f56ba866525552f1838d37fb00534a01"}}}, "metadata": {"references": ["https://www.php.net/manual/en/function.include.php", "https://github.com/FloeDesignTechnologies/phpcs-security-audit/blob/master/Security/Sniffs/BadFunctions/EasyRFISniff.php", "https://en.wikipedia.org/wiki/File_inclusion_vulnerability#Types_of_Inclusion"]}, "severity": "ERROR", "is_ignored": false, "lines": "require dirname(__FILE__).'/../src/ParserService.php';"}}], "errors": []}
```

## Production

Right now SNOW runs daily scans in Jenkins and sends alerts about failing tests to #alerts-snow.  The prodsec team is in the process of fine tuning how and when scans will run, and how to resolve any alerts that come up.  For now failing tests should be non-blocking, but this may change in the future - more details to come on this subject.

Current links to the daily scans:

* https://jenkins.tinyspeck.com/job/security-semgrep-prodsec
* https://jenkins.tinyspeck.com/job/security-semgrep-prodsec-test/


## Help and Feedback

The ProdSec team wants Slack's static analysis tooling to help, not hinder, developers with writing secure code.  If you have suggestions for improving the process of receiving and addressing SNOW findings, please feel free to reach out to us in #triage-prodsec or #proj-static-analysis-non-webapp.


## Alerting

All alerts go to #alerts-snow. Alerts are broken into, Semgrep Alerts and Data Thereom Alerts. 


### Semgrep Alerts
Every day at ~9:00 AM Semgrep will kick off it's daily scan. When every repo is scanned and the results are output, Semgrep will alert out. Semgrep alerts are broken into four sections. 

* Summary
* High 
* Normal 
* Errors

#### Summary

A daily summary of the run's results. 

#### High

Alerts are flagged as high if in the `config.cfg` if the rule triggered matches a rule id within `high_priority_rules_check_id` or if a rule's message matches a string within `high_priority_rules_message`. The following is an example. 
```
[high-priority]
high_priority_rules_check_id =
    languages.golang.slack.potential-code-execution-1

high_priority_rules_message =
    exec
```

#### Normal

All alerts not high, are normal.

#### Errors

Some rules in Semgrep timeout or have another syntax error. If any errors are present the following message will be presented to investigate. 
```
There were errors this run. Check Jenkins https://jenkins.tinyspeck.com/job/security-semgrep-prodsec
```

#### The Anatomy of A Semgrep Alert

An individual alert is broken into the following sections.

* Rule ID - The Semgrep Rule ID
* Message - A description of the vulnerability 
* Link - A direct link to the vulnerability in GitHub
* Code - A brief view of the code. Note that arbitrarily long code (like single line JavaScript libraries) are purposely trimmed. 

*Example*
```
Security Vulnerability Detected in goslackgo
Rule ID: languages.golang.slack.potential-integer-overflow
Message: The size of int in Go is dependent on the system architecture.  The int, uint, and uintptr types are usually 32 bits wide on 32-bit systems and 64 bits wide on 64-bit systems.  On a 64 bit system, if the value passed to the strconv.Atoi() function is bigger (or smaller if negative) than what can be stored in an int32, an integer overflow may occur.
Link: https://slack-github.com/slack/goslackgo/blob/3e910116aa366ed49d23fee5590d7aa9750483d6/wot/slo_calc.go#L101
Code:
    window, err := strconv.Atoi(bucket.Slo.Window)
```  
  
### Other Notes

* There are no Semgrep pull request alerts.
* Only new vulnerabilities are alerted on. 
* Vulnerability data is kept for the duration of how long we keep Jenkins build server console logs. 
* Vulnerabilities use the server `slack` command to send messages to Slack channels. 

### Data Theorem Alerts

Data Theorem Alerts has 2 integrations which are sent to #alerts-snow

* *Slack Alerts for Mobile Apps*: Real-time Alerts for your Mobile Apps via Slack/Microsoft Teams.
* *Slack Alerts for API/Cloud/Web Apps*: Real-time Alerts for your API/Cloud/Web Apps via Slack.

#### Alert Types

* *Daily/Weekly/Monthly Summaries*: Post a summary each day/week/month depending on volume.

* *Priority Alerts*: Real-time alerts on P1 Issues & App/Play Store blockers.

* *real-time alert* will be sent whenever the following happens:
  * When a user adds a comment to a policy violation.
  * When a user closes a policy violation as “won’t fix“.
  * When one or multiple urgent violations were opened by the Data Theorem analyzer.

*Periodic Summaries*
This summary includes total number of assets, number of violations discovered and number of scans completed.

