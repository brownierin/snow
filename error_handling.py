import slack_sdk as slack
import logging
import os
import datetime


class ErrorHandling:
    """
    This class sends errors to a slack channel.
    """

    def __init__(self, channel):
        self.token = os.environ.get("BOT_TOKEN")
        self.slack_sdk = slack.WebClient(token=self.token)
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.INFO)
        self.ts = None
        self.channel = channel
        self.time = datetime.datetime.now()
        self.error_message = f"Errors for scan at {self.time.strftime('%Y-%m-%d %H:%M:%S')}"

    def post_error(self, error):
        """
        This function posts an error to the thread.
        """
        self.find_or_create_thread()
        try:
            resp = self.slack_sdk.chat_postMessage(channel=self.channel, text=error, thread_ts=self.ts)
        except Exception as e:
            logging.warning(e)
            return
        else:
            return resp

    def find_or_create_thread(self):
        """
        This function finds or creates a thread.
        """
        if not self.ts:
            try:
                result = self.slack_sdk.chat_postMessage(channel=self.channel, text=self.error_message)
                self.ts = result["ts"]
            except Exception as e:
                logging.warning(e)
                return
