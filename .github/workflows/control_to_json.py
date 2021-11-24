#!/usr/bin/env python3
# -*- coding: future_fstrings -*-
import sys

input = sys.stdin.read()

input = input.replace("\\", "\\\\").replace("\"", "\\\"")
input = input.replace("\n", "\\n").replace("\t", "\\t")
input = input.replace("`", '\`')

return input
