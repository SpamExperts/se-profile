import logging
import os

import pwd


def setup_logging(logger, filename=None, stream_level=None, watched=False,
                  logdir="/var/log"):
    """Initialize logging for this logger. This add adds a file
    handler to `/var/log/` (or `/tmp/` if writing to /var/log/ is not allowed).

    :param logger: The logger that should be initialized.
    :param filename: The filename.
    :param stream_level: If specified add a stream handler
      and set it to that level
    :param logdir: Path where the log file is going to be written
    """
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    logger.setLevel(logging.DEBUG)

    file_class = logging.FileHandler
    if watched:
        file_class = logging.handlers.WatchedFileHandler

    if filename:
        filename = "%s/%s.log" % (logdir, filename)
        file_handler = file_class(filename)
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.INFO)
        logger.addHandler(file_handler)

    if stream_level is not None:
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(getattr(logging, stream_level))
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)


def setup_script_logging(logger, filename=None, debug=False, info=False,
                         watched=False, logdir="/var/log/"):
    """Shortcut for setting up logging in scripts."""
    if debug:
        stream_level = "DEBUG"
    elif info:
        stream_level = "INFO"
    else:
        stream_level = "CRITICAL"
    setup_logging(logger, filename, stream_level=stream_level,
                  watched=watched, logdir=logdir)
