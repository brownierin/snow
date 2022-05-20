import os
import json
import sys
import logging
import pytest

logger = logging.getLogger(__name__)

SNOW_ROOT = os.path.realpath(os.path.dirname(os.path.realpath(__file__)) + "/../../")

sys.path.insert(0, SNOW_ROOT)
from run_semgrep import regex_sha_match


def test_selected_paths():
    repo = "hello"
    language = "golang"
    paths = [
        "golang-hello-45d1d2b.json",
        "golang-hello-45d1d2b-comparison.json",
        "golang-hello-45d1d2b-fprm.json",
        "golang-hello-again-ad9047b.json",
        "golang-hello-again-ad9047b-fprm.json",
        "golang-hello-friend-ee4e8d2.json",
        "golang-hello-friend-ee4e8d2-comparison.json",
        "golang-hello-friend-ee4e8d2-fprm.json",
    ]
    selected_paths = regex_sha_match(paths, repo, language)
    assert len(selected_paths) == 3


def test_selected_paths_longer_repo_name():
    repo = "hello-again"
    language = "golang"
    paths = [
        "golang-hello-45d1d2b.json",
        "golang-hello-45d1d2b-comparison.json",
        "golang-hello-45d1d2b-fprm.json",
        "golang-hello-again-ad9047b.json",
        "golang-hello-again-ad9047b-fprm.json",
        "golang-hello-friend-ee4e8d2.json",
        "golang-hello-friend-ee4e8d2-comparison.json",
        "golang-hello-friend-ee4e8d2-fprm.json",
    ]
    selected_paths = regex_sha_match(paths, repo, language)
    assert len(selected_paths) == 2
