class GitMergeBaseError(Exception):
    def __init__(self):
        self.message = (
            "The comparison between the Slack fork and the original project failed. "
            "Check the Slack fork git history."
        )


class WebhookUrlError(Exception):
    def __init__(self):
        self.message = "Webhook URL isn't set!"


class WebhookError(Exception):
    def __init__(self):
        self.message = "Webhook failed to send!"
