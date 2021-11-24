#!/usr/bin/env python3
# -*- coding: future_fstrings -*-
# import sys

# results = sys.stdin.read()

# results = results.replace("\\", "\\\\").replace("\"", "\\\"")
# results = results.replace("\n", "\\n").replace("\t", "\\t")
# results = results.replace("`", '\`')

# return results


import json
import os
import subprocess


def open_file(filename):
    with open(filename, 'r+') as f:
        return f.read()


def jsonify(text):
    return json.dumps(text)


def main():
    text = open_file(os.environ['PWD'] + '/results/results_blob.txt')
    body = jsonify(text)
    os.environ['BODY'] = body
    cmd = 'echo "RESULTS=${BODY}" >> $GITHUB_ENV'
    subprocess.run(cmd, shell=True)


if __name__ == '__main__':
    main()
