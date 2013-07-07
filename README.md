# Backuper


**Backuper** is a python script that uploads the given file to the configured dropbox account. It can be used for simple backup procedure, triggered by schedule or some event.


## Version

Version: 0.0.1, TODO: add directory upload support.


## Configuration

Both scripts has "-h" argument to see the arguments list, so try "`python backup.py -h`" for help;

Scripts expect two configuration files:

* `--logger` - a path to logging configuration, if not passed default will be used
* `--config` - a path to application API credentials

Use `install.conf.template` as a template for your credentials config, fill it with you Dropbox application credentials and then pass the path to this file as the `--config` parameter.


## Requirements

To run scripts you will need a Dropbox Python SDK, it can be found on the Dropbox [developers site](https://www.dropbox.com/developers/core/sdk) .

Unzip the archive and run `python setup.py install` to install the sdk.

Also, Python >= 2.7 us required.


## Installation

Before you can run `backup.py` script, you need an access token of the target dropbox account.

To obtain the access token, you need to run `install.py` script first. `--session` argument can override a file path for saving access token data. The same `--session` path that you used for installation must be used with `backup.py`


## Running

After installation is done, you can run `python backup.py /path/to/your/file.zip` to upload the file to the Dropbox. If token is lost or expired you need to repeat installation procedure.



<small>&copy; Licensed under the Apache License, [Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)</small>