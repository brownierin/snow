import checkpoint_out as checkpoint


def test_create_upload_fail_msg():
    post_params = {"test_run": {"repo": "test_repo", "commit_master": "abcdefgh", "commit_head": "ijklmnop"}}
    repo = post_params["test_run"]["repo"]
    master = post_params["test_run"]["commit_master"]
    branch = post_params["test_run"]["commit_head"]
    expected = f"Uploading to checkpoint failed on {repo} for branch commit {branch[:7]} and master commit {master[:7]}"
    assert expected == checkpoint.create_upload_fail_msg(post_params)
