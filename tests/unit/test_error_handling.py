from error_handling import ErrorHandling
import vcr
import os
import configparser


SNOW_ROOT = os.path.realpath(os.path.dirname(os.path.realpath(__file__)) + "/../../")
config = configparser.ConfigParser()
config.read(f"{SNOW_ROOT}/config/test.cfg")
channel = config["general"]["channel"]


def test_create_thread():
    err = ErrorHandling(channel=channel)
    assert err.ts is None
    with vcr.use_cassette(f"{SNOW_ROOT}/tests/unit/fixtures/error_handling_create_thread.yaml"):
        err.find_or_create_thread()
        assert err.ts is not None


def test_find_thread():
    err = ErrorHandling(channel=channel)
    with vcr.use_cassette(f"{SNOW_ROOT}/tests/unit/fixtures/error_handling_create_thread.yaml"):
        err.find_or_create_thread()  # creates thread
        assert err.ts is not None
        ts = err.ts
        with vcr.use_cassette(f"{SNOW_ROOT}/tests/unit/fixtures/error_handling_find_thread.yaml"):
            err.find_or_create_thread()  # finds thread
        assert err.ts == ts


def test_post_error():
    err = ErrorHandling(channel=channel)
    with vcr.use_cassette(f"{SNOW_ROOT}/tests/unit/fixtures/error_handling_create_thread.yaml"):
        err.find_or_create_thread()  # creates thread
        with vcr.use_cassette(f"{SNOW_ROOT}/tests/unit/fixtures/error_handling_post_error.yaml"):
            resp = err.post_error("test")  # posts error
            assert resp["ok"] is True
