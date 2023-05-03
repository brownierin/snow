import pytest

from src.config import *
from src.checkpoint import create_checkpoint_results_json

def pytest_sessionstart(session):
    session.results = dict()

@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    result = outcome.get_result()

    if result.when == 'call':
        item.session.results[item] = result

def pytest_sessionfinish(session, exitstatus):
    # Write results to checkpoint
    checkpoint_results = []

    for item in session.results:
        result = session.results[item]
        checkpoint_results.append({
            "level" : "pass" if result.passed else "failure",
            "case" : item.name,
            "output" : ""
        })

    create_checkpoint_results_json(checkpoint_results)
