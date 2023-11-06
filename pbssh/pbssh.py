"""A wrapper over SSH commands which grabs credentials from Passbolt."""
import argparse
import configparser
import getpass
import json
import logging
import os
import sys
import warnings
from pathlib import Path
from urllib.parse import unquote_plus

import requests
import urllib3

from . import __version__

# Disable some deprecations warnings, not my problem.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", ".*deprecated.*")
import pgpy
from pgpy import PGPKey, PGPMessage

# Use the default logger, will probably be redefined by our custom logger later.
logger = logging.getLogger()


class LoginError(Exception):
    """Autnetication failed with Passbolt API."""


class Passbolt:
    def __init__(
        self,
        base_url: str,
        key_file: Path,
        verify: bool = True,
    ):
        """High level interface to the Passbolt API.

        :param base_url: URL of the Passbolt server with protocol (e.g https://foo.bar)
        :param key_file: Path to GPG key file.
        :param verify: Whether to SSL verify all HTTP requests.
        """
        self.base_url = base_url
        self.ssl_verify = verify
        self.passphrase = None

        self.session = requests.session()
        self.session.verify = verify

        self.key, self.fingerprint = self._load_key(key_file)
        self._login()

    def _load_key(self, path: Path) -> tuple[PGPKey, str]:
        """Load a GPG key from disk.

        :param path: Path to the GPG key on disk.

        :return: Key object and corresponding fingerprint.
        """
        key, _ = PGPKey.from_file(str(path.absolute().resolve()))
        return key, str(key.fingerprint)

    def _verify(self):
        """Fetch the server's identity for verification."""
        endpoint = f"{self.base_url}/auth/verify.json"
        resp = self.session.get(endpoint).json()

        # Note: This method implicility trusts the fingerprint of the target server.
        # We should have a method to specify a fingerprint, and verify it when
        # we first authenticate with the server.
        return resp["body"]

    def _login(self):
        """Login to Passbolt.

        Login to passbolt using the provided GPG key. Interactively requests
        password from the user.
        """
        endpoint = f"{self.base_url}/auth/login.json"
        logger.debug("Attempting login to %s", endpoint)
        self.server_info = self._verify()
        payload = {
            "data": {
                "gpg_auth": {
                    "keyid": self.fingerprint,
                }
            }
        }

        logger.debug("Received fingerprint %s", self.fingerprint)

        # Stage 1, ask the server for GPG info
        post_headers = {"Content-Type": "application/json; charset=utf-8"}
        resp = self.session.post(
            endpoint,
            headers=post_headers,
            json=payload,
        )
        headers = dict(resp.headers)

        # Received GPG message
        gpgauth_user_auth_token = unquote_plus(headers["X-GPGAuth-User-Auth-Token"])
        gpgauth_user_auth_token = gpgauth_user_auth_token.replace("\\", "")

        # Stage 2, decrypt nonce and send it back.
        logging.debug("Received nonce from API")
        pgp_message = PGPMessage.from_blob(gpgauth_user_auth_token)
        userid = self.key.userids[0]

        while self.passphrase is None:
            try:
                self.passphrase = getpass.getpass(prompt=f"Passbolt {userid.email}: ")
                with self.key.unlock(self.passphrase):
                    nonce = str(self.key.decrypt(pgp_message).message.decode())
            except pgpy.errors.PGPDecryptionError as e:
                logging.debug(e)
                print("Passphrase was incorrect! Try again.")
                self.passphrase = None

        logging.debug("Decrypted nonce")

        payload["data"]["gpg_auth"]["user_token_result"] = nonce
        resp = self.session.post(
            endpoint,
            headers=post_headers,
            json=payload,
        )
        headers = dict(resp.headers)

        # If the response isn't 200, authentication failed.
        if resp.status_code != 200:
            logging.error("Failed to authenticate")
            logging.error(resp.text)
            raise LoginError("Authentication failed.")
        logging.debug("Successfully authenticated")

    def _get_resources(self) -> list[dict]:
        """Get a list of all resources on Passbolt.

        Reference:
            https://api-reference.passbolt.com/#/Resource/getPasswords

        :return: List of resources with various metadata.
        """
        endpoint = f"{self.base_url}/resources.json"
        resp = self.session.get(endpoint)
        return resp.json()["body"]

    def _get_resource(self, id: str) -> dict:
        """Get more info about a particular resource.

        Reference:
            https://api-reference.passbolt.com/#/Resource/getPassword

        :param id: ID of the resource to retrieve.

        :return: Metadata about the resource.
        """
        endpoint = f"{self.base_url}/resources/{id}.json"
        resp = self.session.get(endpoint)
        return resp.json()["body"]

    def _get_secret(self, id: str) -> str:
        """Given a resource ID, get the corresponding password.

        Reference:
            https://api-reference.passbolt.com/#/Secret/get_secrets_resource__resourceId__json

        :param id: ID of the resource (entry) password to retrieve.

        :return: Password from the entry.
        """
        endpoint = f"{self.base_url}/secrets/resource/{id}.json"
        resp = self.session.get(endpoint)

        data = resp.json()["body"]["data"]
        pgp_message = PGPMessage.from_blob(data)

        with self.key.unlock(self.passphrase):
            payload = self.key.decrypt(pgp_message).message

        return json.loads(payload)["password"]

    def search(self, uri: str, username: str = None) -> dict:
        """Search Passbolt for an entry for uri and optionally username.

        :param uri: URI to match within resource.
        :param username: Username to match within resource.

        :return: Metadata and secret if exists, otherwise empty dict.
        """
        resources = self._get_resources()
        resource = None
        for i in resources:
            if i["uri"] == uri:
                if username is not None and i["username"] == username:
                    resource = i
                    break
                elif username is None:
                    resource = i
                    break
        else:
            logger.warning(
                "Unable to find matching passbolt entry for host %s, user %s",
                uri,
                username,
            )
            logger.warning("Falling back to password auth.")
            return {}

        resource["secret"] = self._get_secret(resource["id"])
        return resource


def _build_parser(exit_on_error: bool = True) -> argparse.ArgumentParser:
    """Build the CLI parser.

    :param exit_on_error: Terminate the program (sys.exit) if there is a
                          semantic failure with CLI flags.
    :return: Argument parser object.
    """
    parser = argparse.ArgumentParser(
        add_help=False,
        description=__doc__,
        exit_on_error=exit_on_error,
    )
    parser.add_argument(
        "HOST",
        action="store",
        metavar="HOSTNAME",
        help="Host to SSH to.",
    )
    parser.add_argument(
        "-p",
        "--print",
        action="store_true",
        help="Just print the matching password, don't attempt SSH.",
    )

    # Passthrough rest of opts to ssh.
    parser.add_argument(
        "SSH_ARGS",
        nargs=argparse.REMAINDER,
        help="Remaining arguments are passed through to SSH.",
    )

    # Generic
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "-h",
        "--help",
        action="help",
        default=argparse.SUPPRESS,
        help="Show this help message and exit.",
    )

    return parser


def _setup_logging(lvl: int) -> logging.Logger:
    """Setup the default logging policy.

    :param lvl: Log level.
    :return: Configured logger.
    """
    if lvl == 0:
        log_level = logging.WARNING
    elif lvl == 1:
        log_level = logging.WARNING
    elif lvl == 2:
        log_level = logging.INFO
    else:
        log_level = logging.DEBUG

    logging.basicConfig(
        level=logging.ERROR,  # Third party libs use this log level
        format="[%(asctime)s %(name)s %(levelname)-8s - %(funcName)20s()] - %(message)s",
    )

    logger = logging.getLogger("pbssh")
    # My code uses this log level
    logger.setLevel(log_level)
    logger.debug(
        "Initialized logger with log level %s (verbose=%s)",
        logging._levelToName[log_level],
        lvl,
    )

    return logger


def _first_time(path):
    """Show a helpful message the first time this command is run."""

    msg = f"""
Hi there! It looks like this is the first time you are using pbssh.

We'll go ahead and create the default configuration file at {path}, you should
edit it to match your Passbolt configuration. You won't see this message after
that.

Incase something isn't working right and you want to regenerate that config
file, just delete it and run `pbssh`, you'll be greeted by this message again.
"""
    print(msg)
    config = configparser.ConfigParser()
    config["Passbolt"] = {
        "base_url": "https://your-passbolt-url-here",
        "gpgkey_path": "~/.passbolt-key.asc",
    }
    with open(path, "w") as f:
        config.write(f)


def load_config(path: Path) -> configparser.ConfigParser:
    """Load the config file."""
    config = configparser.ConfigParser()
    config.read(path)
    return config


def _ssh(host: str, password: str, args: list[str]):
    """Replace this process with an SSH session.

    Note, this function will never return. The currently running Python process
    is replaced with the SSH call.

    :param host: Host to pass to SSH command.
    :param password: Password to use when logging in. If falsy, sshpass is not
                     used and this param is ignored.
    :param args: Arguments to pass to the SSH command.
    """
    if not password:
        command = "ssh"
        args = ["ssh", host, *args]
        logger.debug("Password not set, not using sshpass.")
    else:
        command = "sshpass"
        args = ["sshpass", "-e", "ssh", host, *args]
        logger.debug("Password set, using sshpass.")

    env = os.environ.copy()
    env["SSHPASS"] = password
    logger.debug("Setup environment for execvpe. Goodbye!")
    os.execvpe(command, args, env)


def main() -> int:
    """Entrypoint from CLI."""
    parser = _build_parser()
    args = parser.parse_args()
    args = vars(args)

    global logger
    logger = _setup_logging(args["verbose"])

    config_file_path = Path().home() / ".pbssh"
    logger.debug("Config file path: %s", config_file_path)
    if not config_file_path.is_file():
        logger.debug("Config file not found, show first time message")
        _first_time(config_file_path)
        return 0

    logger.debug("Found config file, loading...")
    config = load_config(config_file_path)

    key_file = Path(config["Passbolt"]["gpgkey_path"]).expanduser()
    base_url = config["Passbolt"]["base_url"]

    logger.info("Base URL: %s", base_url)
    logger.info("Keyfile: %s", key_file)

    api = Passbolt(
        base_url=base_url,
        key_file=key_file,
        verify=False,
    )

    try:
        username, host = args["HOST"].split("@")
        logging.debug("Parsed username and host %s@%s", username, host)
    except ValueError:
        username, host = getpass.getuser(), args["HOST"]
        logging.debug("Username not specified, %s@%s", username, host)

    item = api.search(uri=host, username=username)
    if args["print"]:
        logging.debug("Received --print, showing and exiting.")
        print(item.get("secret", ""))
        return 0

    _ssh(args["HOST"], item.get("secret", ""), args["SSH_ARGS"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
