"""
/**
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

 Script that obtains access token for future usage. Run it before backup.py is used.

 usage: backup.py [-h] [-l LOGGER] [-c CONFIG] [-s SESSION]

 CONFIG - API credentials
 SESSION - will be used for saving obtained access token
"""

__author__ = 'Alexey Rosolovskiy'

import argparse
import sys
import logging
import logging.config
from os import path
from whichdb import whichdb

from dropbox import session

from backup import SessionStorage, BackupConfig, override_logger_name


LOGGER_NAME = "install"
override_logger_name(LOGGER_NAME)


def main(argv):
    parser = argparse.ArgumentParser()
    cfg = parser.add_argument_group("configuration")
    cfg.add_argument("-l", "--logger", help="path to the logging config", default="./logger.conf")
    cfg.add_argument("-c", "--config", help="path to the application config", default="./install.conf")
    cfg.add_argument("-s", "--session", help="path to the session storage", default="./session.shelve")
    args = parser.parse_args(argv)
    logging.config.fileConfig(args.logger)
    log = logging.getLogger(LOGGER_NAME)
    log.info("Logger initialized with configuration file=%s", args.logger)
    validate_arguments(args)
    backup_config = BackupConfig(args.config)
    session_storage = SessionStorage(args.session, read_only=False)
    access_token = obtain_access_token(backup_config, log)
    session_storage.access_token = access_token
    log.info("Access token successfully obtained and saved in session storage, now you can run backup.py script")


def validate_arguments(args):
    if not path.exists(args.config):
        raise ValueError("Can not find application config: %s" % args.config)
    if whichdb(args.session):
        raise ValueError("Session storage file (%s) already exists, please, choose another one or delete it first" %
                         args.session)


def obtain_access_token(backup_config, log):
    log.debug("Application key to use: \"%s\"", backup_config.app_key)
    log.debug("Access type to use: \"%s\"", backup_config.access_type)
    sess = session.DropboxSession(backup_config.app_key, backup_config.app_secret, backup_config.access_type)
    log.debug("Dropbox session is configured")
    log.info("Obtaining a request token...")
    request_token = sess.obtain_request_token()
    log.info("Request token is received")
    log.debug("Building authorization url:")
    url = sess.build_authorize_url(request_token)
    log.info("URL: %s", url)
    log.info("Please visit this website and press the 'Allow' button, then hit 'Enter' here.")
    raw_input()
    log.info("Obtaining an access token, it will fail if you did not visit the URL above and hit 'Allow'")
    access_token = sess.obtain_access_token(request_token)
    log.info("Access token is received")
    return access_token


if __name__ == "__main__":
    main(sys.argv[1:])
