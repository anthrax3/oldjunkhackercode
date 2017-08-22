import argparse
import fnmatch
import logging
import os
import sys

import six

from ..core import config
from ..core import constants
from ..core import manager
from ..core import utils


# BASE_CONFIG = 'junkhacker.yaml'
# logging.basicConfig(level=logging.CRITICAL)
logger = logging.getLogger()
# logger.setLevel(logging.CRITICAL)
VERSION = '0.1'
formatter_names = set(['csv', 'html', 'json', 'screen', 'text', 'xml'])

def _init_logger(debug=False, log_format=None):
    '''Initialize the logger

    :param debug: Whether to enable debug mode
    :return: An instantiated logging instance
    '''
    logger.handlers = []
    log_level = logging.INFO
    if debug:
        log_level = logging.DEBUG

    if not log_format:
        # default log format
        log_format_string = constants.log_format_string
    else:
        log_format_string = log_format

    logging.captureWarnings(True)

    logger.setLevel(log_level)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(log_format_string))
    logger.addHandler(handler)
    logger.debug("logging initialized")


def _get_options_from_ini(ini_path, target):
    """Return a dictionary of config options or None if we can't load any."""
    ini_file = None

    if ini_path:
        ini_file = ini_path
    else:
        junkhacker_files = []

        for t in target:
            for root, dirnames, filenames in os.walk(t):
                for filename in fnmatch.filter(filenames, '.junkhacker'):
                    junkhacker_files.append(os.path.join(root, filename))

        if len(junkhacker_files) > 1:
            logger.error('Multiple .junkhacker files found - scan separately or '
                         'choose one with --ini\n\t%s',
                         ', '.join(junkhacker_files))
            sys.exit(2)

        elif len(junkhacker_files) == 1:
            ini_file = junkhacker_files[0]
            logger.info('Found project level .junkhacker file: %s',
                        junkhacker_files[0])

    if ini_file:
        return utils.parse_ini_file(ini_file)
    else:
        return None


# def _init_extensions():
#     from ..core import extension_loader
#     return extension_loader.MANAGER


def _log_option_source(arg_val, ini_val, option_name):
    """It's useful to show the source of each option."""
    if arg_val:
        logger.info("Using command line arg for %s", option_name)
        return arg_val
    elif ini_val:
        logger.info("Using .junkhacker arg for %s", option_name)
        return ini_val
    else:
        return None


def _running_under_virtualenv():
    if hasattr(sys, 'real_prefix'):
        return True
    elif sys.prefix != getattr(sys, 'base_prefix', sys.prefix):
        return True


# def _get_profile(config, profile_name, config_path):
#     profile = {}
#     if profile_name:
#         profiles = config.get_option('profiles') or {}
#         profile = profiles.get(profile_name)
#         if profile is None:
#             raise utils.ProfileNotFound(config_path, profile_name)
#         logger.debug("read in legacy profile '%s': %s", profile_name, profile)
#     else:
#         profile['include'] = set(config.get_option('tests') or [])
#         profile['exclude'] = set(config.get_option('skips') or [])
#     return profile


def _log_info(args, profile):
    inc = ",".join([t for t in profile['include']]) or "None"
    exc = ",".join([t for t in profile['exclude']]) or "None"
    logger.info("profile include tests: %s", inc)
    logger.info("profile exclude tests: %s", exc)
    logger.info("cli include tests: %s", args.tests)
    logger.info("cli exclude tests: %s", args.skips)


def main():
    # bring our logging stuff up as early as possible
    debug = ('-d' in sys.argv or '--debug' in sys.argv)
    _init_logger(debug)
    # extension_mgr = _init_extensions()

    # baseline_formatters = [f.name for f in filter(lambda x:
    #                                               hasattr(x.plugin,
    #                                                       '_accepts_baseline'),
    #                                               extension_mgr.formatters)]

    # now do normal startup
    parser = argparse.ArgumentParser(
        description='JunkHacker - a Python static analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        'targets', metavar='targets', type=str, nargs='+',
        help='source file(s) or directory(s) to be tested'
    )
    parser.add_argument(
        '-r', '--recursive', dest='recursive',
        action='store_true', help='find and process files in subdirectories'
    )
    parser.add_argument(
        '-a', '--aggregate', dest='agg_type',
        action='store', default='file', type=str,
        choices=['file', 'vuln'],
        help='aggregate output by vulnerability (default) or by filename'
    )
    parser.add_argument(
        '-n', '--number', dest='context_lines',
        action='store', default=3, type=int,
        help='maximum number of code lines to output for each issue'
    )
    parser.add_argument(
        '-c', '--configfile', dest='config_file',
        action='store', default=None, type=str,
        help='optional config file to use for selecting plugins and '
             'overriding defaults'
    )
    parser.add_argument(
        '-p', '--profile', dest='profile',
        action='store', default=None, type=str,
        help='profile to use (defaults to executing all tests)'
    )
    parser.add_argument(
        '-t', '--tests', dest='tests',
        action='store', default=None, type=str,
        help='comma-separated list of test IDs to run'
    )
    parser.add_argument(
        '-s', '--skip', dest='skips',
        action='store', default=None, type=str,
        help='comma-separated list of test IDs to skip'
    )
    parser.add_argument(
        '-l', '--level', dest='severity', action='count',
        default=1, help='report only issues of a given severity level or '
                        'higher (-l for LOW, -ll for MEDIUM, -lll for HIGH)'
    )
    parser.add_argument(
        '-i', '--confidence', dest='confidence', action='count',
        default=1, help='report only issues of a given confidence level or '
                        'higher (-i for LOW, -ii for MEDIUM, -iii for HIGH)'
    )
    output_format = 'screen' if sys.stdout.isatty() else 'txt'
    parser.add_argument(
        '-f', '--format', dest='output_format', action='store',
        default=output_format, help='specify output format',
        choices=sorted(formatter_names)
    )
    parser.add_argument(
        '-o', '--output', dest='output_file', action='store', nargs='?',
        type=argparse.FileType('w'), default=sys.stdout,
        help='write report to filename'
    )
    parser.add_argument(
        '-v', '--verbose', dest='verbose', action='store_true',
        help='output extra information like excluded and included files'
    )
    parser.add_argument(
        '-d', '--debug', dest='debug', action='store_true',
        help='turn on debug mode'
    )
    parser.add_argument(
        '--ignore-nosec', dest='ignore_nosec', action='store_true',
        help='do not skip lines with # nosec comments'
    )
    parser.add_argument(
        '-x', '--exclude', dest='excluded_paths', action='store',
        default='', help='comma-separated list of paths to exclude from scan '
                         '(note that these are in addition to the excluded '
                         'paths provided in the config file)'
    )
    parser.add_argument(
        '-b', '--baseline', dest='baseline', action='store',
        default=None, help='path of a baseline report to compare against '
                           '(only JSON-formatted files are accepted)'
    )
    parser.add_argument(
        '--ini', dest='ini_path', action='store', default=None,
        help='path to a .junkhacker file that supplies command line arguments'
    )
    parser.add_argument(
        '--version', action='version',
        version='%(prog)s {version}'.format(version=VERSION)
    )
    parser.set_defaults(debug=False)
    parser.set_defaults(verbose=False)
    parser.set_defaults(ignore_nosec=False)

    # blacklist_info = []
    # for a in six.iteritems(extension_mgr.blacklist):
    #     for b in a[1]:
    #         blacklist_info.append('%s\t%s' % (b['id'], b['name']))

    # plugin_list = '\n\t'.join(sorted(set(blacklist_info)))
    parser.epilog = ('Happy Junk Hacking!')
    # parser.epilog = ('The following tests were discovered and'
    #                  ' loaded:\n\t{0}\n'.format(plugin_list))

    # setup work - parse arguments, and initialize JunkHackerManager
    args = parser.parse_args()

    try:
        conf = config.JunkHackerConfig(config_file=args.config_file)
    except utils.ConfigError as e:
        logger.error(e)
        sys.exit(2)

    # Handle .junkhacker files in projects to pass cmdline args from file
    ini_options = _get_options_from_ini(args.ini_path, args.targets)
    if ini_options:
        # prefer command line, then ini file
        args.excluded_paths = _log_option_source(args.excluded_paths,
                                                 ini_options.get('exclude'),
                                                 'excluded paths')

        args.skips = _log_option_source(args.skips, ini_options.get('skips'),
                                        'skipped tests')

        args.tests = _log_option_source(args.tests, ini_options.get('tests'),
                                        'selected tests')
        # TODO(tmcpeak): any other useful options to pass from .junkhacker?

    # if the log format string was set in the options, reinitialize
    if conf.get_option('log_format'):
        log_format = conf.get_option('log_format')
        _init_logger(debug, log_format=log_format)


    mgr = manager.JunkHackerManager(conf, args.agg_type, args.debug,
                                    verbose=args.verbose,
                                    ignore_nosec=args.ignore_nosec)

    if args.baseline is not None:
        try:
            with open(args.baseline) as bl:
                data = bl.read()
                mgr.populate_baseline(data)
        except IOError:
            logger.warning("Could not open baseline report: %s", args.baseline)
            sys.exit(2)

        # if args.output_format not in baseline_formatters:
        #     logger.warning('Baseline must be used with one of the following '
        #                    'formats: ' + str(baseline_formatters))
        #     sys.exit(2)

    if args.output_format != "json":
        if args.config_file:
            logger.info("using config: %s", args.config_file)

        logger.info("running on Python %d.%d.%d", sys.version_info.major,
                    sys.version_info.minor, sys.version_info.micro)

    # initiate file discovery step within JunkHacker Manager
    mgr.discover_files(args.targets, args.recursive, args.excluded_paths)
    logger.debug("mgr.files_list is now %s", mgr.files_list)
    logger.debug("len(mgr.files_list) is now %s", len(mgr.files_list))

    # initiate execution of tests within JunkHacker Manager
    mgr.run_tests()
    # logger.debug(mgr.ma)
    logger.debug(mgr.metrics)

    # trigger output of results by JunkHacker Manager
    sev_level = constants.RANKING[args.severity - 1]
    conf_level = constants.RANKING[args.confidence - 1]
    mgr.output_results(args.context_lines,
                         sev_level,
                         conf_level,
                         args.output_file,
                         args.output_format)

    # return an exit code of 1 if there are results, 0 otherwise
    if mgr.results_count(sev_filter=sev_level, conf_filter=conf_level) > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
