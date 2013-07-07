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

 Script that uploads the given file to the configured dropbox account.

 usage: backup.py [-h] [-l LOGGER] [-c CONFIG] [-s SESSION] file

 CONFIG - API credentials (the same as was used for install.py)
 SESSION - is a path to access token storage, created by install.py script
"""

__author__ = 'Alexey Rosolovskiy'

import argparse
import sys
import logging
import logging.config
from os import path, stat
import ConfigParser
import shelve
from whichdb import whichdb

from dropbox import client, rest, session

LOGGER_NAME = "backup"
EXIT_SUCCESS = 0
EXIT_FAILURE = 1
BYTES_IN_MB = 1024 * 1024


def main(argv):
    parser = argparse.ArgumentParser()
    cfg = parser.add_argument_group("configuration")
    cfg.add_argument("-l", "--logger", help="path to the logging config", default="./logger.conf")
    cfg.add_argument("-c", "--config", help="path to the application config", default="./install.conf")
    cfg.add_argument("-s", "--session", help="path to the session storage", default="./session.shelve")
    bkp = parser.add_argument_group("backup")
    bkp.add_argument("file", help="path to the backup target")
    args = parser.parse_args(argv)
    logging.config.fileConfig(args.logger)
    log = logging.getLogger(LOGGER_NAME)
    log.info("Logger initialized with configuration file=%s", args.logger)
    validate_arguments(args)
    backup_config = BackupConfig(args.config)
    session_storage = SessionStorage(args.session)
    result = upload_file(backup_config, session_storage, args.file, log)
    log.debug("Exiting...")
    exit(EXIT_SUCCESS if result else EXIT_FAILURE)


def validate_arguments(args):
    """
    Validates passed arguments,
    throws exception is something is wrong
    """
    if not path.exists(args.config):
        raise ValueError("Can not find application config: %s" % args.config)
    if not whichdb(args.session):
        raise ValueError("Can not find session storage file (%s), please, run \"install.py\" first" % args.session)
    if not path.exists(args.file):
        raise ValueError("Can not find file \"%s\" for backup" % args.file)


def override_logger_name(logger_name):
    """
    Helper function for other modules to override local logger name
    """
    global LOGGER_NAME
    LOGGER_NAME = logger_name


def upload_file(backup_config, session_storage, _file, log):
    """
    Uploads passed file to the dropbox;

    Parameters:
        backup_config - BackupConfig instance
        session_storage - SessionStorage instance
        file - a path to the file for uploading
        log - logger instance
    Returns:
        True if data is uploaded, else False
    """
    assert not path.isdir(_file), "Directory support not implemented yet"
    log.debug("Application key to use: \"%s\"", backup_config.app_key)
    log.debug("Access type to use: \"%s\"", backup_config.access_type)
    sess = session.DropboxSession(backup_config.app_key, backup_config.app_secret, backup_config.access_type)
    log.debug("Dropbox session is initialized with application configuration")
    log.debug("Reading session from storage...")
    access_token = session_storage.access_token
    log.debug("Injecting access token into the initialized session")
    sess.set_token(access_token.key, access_token.secret)
    log.debug("Dropbox session is configured")
    _client = client.DropboxClient(sess)
    log.debug("Fetching quota information...")
    account_info = _client.account_info()
    free_mb = (account_info['quota_info']['quota'] - account_info['quota_info']['shared']
               - account_info['quota_info']['normal']) / BYTES_IN_MB
    log.info("%s has %dMB free space of %dMB", account_info['display_name'],
             free_mb,
             account_info['quota_info']['quota'] / BYTES_IN_MB)
    file_sz_mb = stat(_file).st_size / float(BYTES_IN_MB)
    log.info("%s size: %0.3fMB", _file, file_sz_mb)
    if free_mb <= file_sz_mb:
        log.warn("A file for uploading is bigger than free space user has")
    log.info("Starting upload...")
    with open(_file, 'rb') as f:
        response = _client.put_file(_build_dropbox_filename(_file), f, overwrite=True,
                                    parent_rev=_get_last_revision(_client, _file, log))
    if response:
        log.info("Uploaded %s, revision: %s, modified: %s, path: %s", response['size'],
                 response['rev'], response['modified'], response['path'])
        return True
    else:
        log.error("File was not uploaded...")
        return False


def _get_last_revision(_client, _file, log):
    """
    Returns a last file revision or None

    Parameters:
        _client - initialized drobpox client
        _file - a local file path to check
        log - initialized logger
    """
    assert not path.isdir(_file), "Directory support not implemented yet"
    remote_filename = _build_dropbox_filename(_file)
    log.info("Requesting metadata for %s", remote_filename)
    try:
        file_metadata = _client.metadata(remote_filename)
    except rest.ErrorResponse as e:
        # uploading for the first ime
        log.debug(e)
        not_found = e.status == 404
        if not_found:
            log.info("No metadata is received, probably it is the first attempt to upload the given file")
            return None
        else:
            raise e
    else:
        assert not file_metadata.get('is_dir', False), "Directory support not implemented yet"
        log.info("Metadata received, size %s, revision: %s, modified: %s", file_metadata.get('size'),
             file_metadata.get('rev'), file_metadata.get('modified'))
        return file_metadata.get('rev', None)


def _build_dropbox_filename(_file):
    return "/" + path.basename(_file)


class BackupConfig(object):
    """
    Reads configuration file passed to the constructor,
    options can be accessed as instance attributes
    """

    def __init__(self, config_file):
        """
        Parameters:
            config_file - a path to the configuration file
        """
        self.cfg = ConfigParser.SafeConfigParser()
        assert config_file in self.cfg.read(config_file)
        self.section = "dropbox"
        self.log = logging.getLogger(LOGGER_NAME)
        self.log.info("Backup config initialized with configuration file=%s", config_file)

    def __getattr__(self, item):
        """
        Returns option value related to passed attribute name;
        This implementation reads options only from "drobpox" section.
        """
        self.log.debug("Reading configuration option: \"%s\"", item)
        return self.cfg.get(self.section, str(item))


class SessionStorage(object):
    """
    Represents persistent storage for session data;
    Stores access_token data in the passed session storage file
    """

    _ACCESS_TOKEN_KEY = "access_token"

    def __init__(self, session_file, read_only=True, file_mode=0640):
        """
        Parameters:
            session_file - a path to use for saving data, side-affect:
                an extension can be added under the hood
            read_only - if True opens database in client mode, throws an exception
                if file is not found or can not be accessed;
                if False - then a new file creation attempt will be performed
            file_mode - a file mode to use while creating file (not used)
        """
        flag = "r" if read_only else "c"
        self.db = shelve.open(session_file, flag, protocol=2)
        self.log = logging.getLogger(LOGGER_NAME)
        self.log.info("Session storage initialized with file=%s", session_file)

    @property
    def access_token(self):
        return self.db[self._ACCESS_TOKEN_KEY]

    @access_token.setter
    def access_token(self, value):
        self.db[self._ACCESS_TOKEN_KEY] = value
        self.db.sync()

    def __del__(self):
        self.db.close()


if __name__ == "__main__":
    main(sys.argv[1:])