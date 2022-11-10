from src.config import *
from src.util import remove_scheme_from_url


def trim_repo_list(repos):
    return [repo.split("/")[-1] for repo in repos]


def get_repo_list():
    """
    Grabs all enabled repository names across all languages
    """
    repos = []
    enabled_filename = set_enabled_filename()
    for language in CONFIG.sections():
        if language.find("language-") != -1:
            filename = f"{LANGUAGES_DIR}{CONFIG[language]['language']}/{enabled_filename}"
            with open(filename) as f:
                enabled = f.read().splitlines()
            repos = repos + [remove_scheme_from_url(repo) for repo in enabled]
    return repos
