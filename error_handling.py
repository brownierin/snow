import slack_sdk as slack
import logging
import os


class ErrorHandling:
    """
    This class sends errors to a slack channel.
    """

    def __init__(self, channel):
        self.slack_sdk = slack.WebClient(token=os.environ.get("BOT_TOKEN"))
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.INFO)
        self.ts = None
        self.channel = channel

    def post_error(self, error):
        """
        This function posts an error to the thread.
        """
        self.find_or_create_thread()
        try:
            self.slack_sdk.chat_postMessage(channel=self.channel, text=error, thread_ts=self.ts)
        except Exception as e:
            logging.warning(e)
            return

    def find_or_create_thread(self):
        """
        This function finds or creates a thread.
        """
        if not self.ts:
            # response = self.slack_sdk.conversations_open(channel=self.channel)
            # self.ts = response["channel"]["thread_ts"]
            try:
                result = self.slack_sdk.chat_postMessage(channel=self.channel, text="Errors")
                self.ts = result["ts"]
            except Exception as e:
                logging.warning(e)
                return
