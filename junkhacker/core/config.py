import logging

import six
import yaml

from . import constants
from . import utils


logger = logging.getLogger(__name__)


class JunkHackerConfig():
    def __init__(self, config_file=None):
        '''Attempt to initialize a config dictionary from a yaml file.

        Error out if loading the yaml file fails for any reason.
        :param config_file: The JunkHacker yaml config file

        :raises junkhacker.utils.ConfigError: If the config is invalid or
            unreadable.
        '''
        self.config_file = config_file
        self._config = {}

        if config_file:
            try:
                f = open(config_file, 'r')
            except IOError:
                raise utils.ConfigError("Could not read config file.",
                                        config_file)

            try:
                self._config = yaml.safe_load(f)
                self.validate(config_file)
            except yaml.YAMLError:
                raise utils.ConfigError("Error parsing file.", config_file)

            # valid config must be a dict
            if not isinstance(self._config, dict):
                raise utils.ConfigError("Error parsing file.", config_file)

        else:
            # use sane defaults
            self._config['plugin_name_pattern'] = '*.py'
            self._config['include'] = ['*.py', '*.pyw']

        self._init_settings()

    def get_option(self, option_string):
        '''Returns the option from the config specified by the option_string.

        '.' can be used to denote levels, for example to retrieve the options
        from the 'a' profile you can use 'profiles.a'
        :param option_string: The string specifying the option to retrieve
        :return: The object specified by the option_string, or None if it can't
        be found.
        '''
        option_levels = option_string.split('.')
        cur_item = self._config
        for level in option_levels:
            if cur_item and (level in cur_item):
                cur_item = cur_item[level]
            else:
                return None

        return cur_item

    def get_setting(self, setting_name):
        if setting_name in self._settings:
            return self._settings[setting_name]
        else:
            return None

    @property
    def config(self):
        '''Property to return the config dictionary

        :return: Config dictionary
        '''
        return self._config

    def _init_settings(self):
        '''This function calls a set of other functions (one per setting)

        This function calls a set of other functions (one per setting) to build
        out the _settings dictionary.  Each other function will set values from
        the config (if set), otherwise use defaults (from constants if
        possible).
        :return: -
        '''
        self._settings = {}

    def validate(self, path):
        '''Validate the config data.'''
        legacy = False
        message = ("Config file has an include or exclude reference "
                   "to legacy test '{0}' but no configuration data for "
                   "it. Configuration data is required for this test. "
                   "Please consider switching to the new config file "
                   "format, the tool 'junkhacker-config-generator' can help "
                   "you with this.")

        def _test(key, block, exclude, include):
            if key in exclude or key in include:
                if self._config.get(block) is None:
                    raise utils.ConfigError(message.format(key), path)
