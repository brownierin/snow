import logging
from textwrap import dedent


class GitMergeBaseError(Exception):
    def __init__(self):
        self.message = (
            "The comparison between the Slack fork and the original project failed. "
            "Check the Slack fork git history."
        )


class WebhookUrlError(Exception):
    def __init__(self):
        self.message = "Webhook URL isn't set!"


class FilePermissionsError(Exception):
    def __init__(self, file, stdout):
        self.file = file
        self.message = f"Unable to change file permissions on {file}"
        self.stdout = stdout
        logging.error(super().__str__())

    def __str__(self):
        str = f"""\
            {self.message}
            Error from cmd: {self.stdout}
        """
        return dedent(str)
