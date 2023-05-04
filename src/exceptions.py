class GitMergeBaseError(Exception):
    def __init__(self):
        self.message = (
            "The comparison between the Slack fork and the original project failed. "
            "Check the Slack fork git history."
        )


class WebhookUrlError(Exception):
    def __init__(self):
        self.message = "Webhook URL isn't set!"


class invalidSha1Error(Exception):
    def __init__(self):
        self.message = "SHA1 isn't valid!"

    def __str__(self):
        return self.message


class FalsePositiveFileDoesNotExist(Exception):
    def __init__(self, filepath):
        self.filepath = filepath

    def __str__(self):
        return (
            f"The false positive file '{self.filepath}' doesn't exists. Verify the codebase isn't "
            "missing its false_positives.json file."
        )
