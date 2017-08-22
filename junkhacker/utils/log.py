"""
  junkhacker.utils.log
  ~~~~~~~~~~~~~~~
"""
import logging
# logging.basicConfig(level=logging.CRITICAL)


# LOGGING_FMT = '%(asctime)s - %(levelname)3s] %(filename)s::%(funcName)s(%(lineno)d) - %(message)s'
LOGGING_FMT = '%(filename)s::%(funcName)s(%(lineno)d) - %(message)s'


def removeOtherHandlers(to_keep=None):
  for hdl in logger.handlers:
    if hdl != to_keep:
      logger.removeHandler(hdl)


def enableLogger(to_file=None):
  logger.setLevel(logging.DEBUG)
  # logger.setLevel(logging.CRITICAL)
  ch = logging.StreamHandler() if not to_file else logging.FileHandler(to_file, mode='w')
  ch.setLevel(logging.DEBUG)
  # ch.setLevel(logging.CRITICAL)
  fmt = logging.Formatter(LOGGING_FMT)
  ch.setFormatter(fmt)
  logger.addHandler(ch)
  removeOtherHandlers(ch)

# logging.basicConfig(level=logging.DEBUG, handler=logging.NullHandler)
logger = logging.getLogger('junkhacker')
removeOtherHandlers()

