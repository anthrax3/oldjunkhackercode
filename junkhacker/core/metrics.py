import collections
import logging

from . import constants

logger = logging.getLogger()


class Metrics(object):
    """JunkHacker metric gathering.

    This class is a singleton used to gather and process metrics collected when
    processing a code base with JunkHacker. Metric collection is stateful, that
    is, an active metric block will be set when requested and all subsequent
    operations will effect that metric block until it is replaced by a setting
    a new one.
    """

    def __init__(self):
        self.data = dict()
        self.data['_totals'] = {'loc': 0, 'nosec': 0}

        # initialize 0 totals for criteria and rank; this will be reset later
        for rank in constants.RANKING:
            for criteria in constants.CRITERIA:
                self.data['_totals']['{0}.{1}'.format(criteria[0], rank)] = 0

    def begin(self, fname):
        """Begin a new metric block.

        This starts a new metric collection name "fname" and makes is active.

        :param fname: the metrics unique name, normally the file name.
        """
        self.data[fname] = {'loc': 0, 'nosec': 0}
        self.current = self.data[fname]

    def note_nosec(self, num=1):
        """Note a "nosec" commnet.

        Increment the currently active metrics nosec count.

        :param num: number of nosecs seen, defaults to 1
        """
        self.current['nosec'] += num

    def count_locs(self, lines):
        """Count lines of code.

        We count lines that are not empty and are not comments. The result is
        added to our currently active metrics loc count (normally this is 0).

        :param lines: lines in the file to process
        """
        def proc(line):
            tmp = line.strip()
            return bool(tmp and not tmp.startswith(b'#'))

        self.current['loc'] += sum(proc(line) for line in lines)

    def count_issues(self, scores):
        self.current.update(self._get_issue_counts(scores))

    def aggregate(self):
        """Do final aggregation of metrics."""
        c = collections.Counter()
        for fname in self.data:
            c.update(self.data[fname])
        self.data['_totals'] = dict(c)

    def _get_issue_counts(self, scores):
        """Get issue counts aggregated by confidence/severity rankings.

        :param scores: list of scores to aggregate / count
        :return: aggregated total (count) of issues identified
        """
        issue_counts = {'SEVERITY.LOW':0}

        # Just a hack until I fix score to be a set
        scorez = scores[0]
        logger.error("scores are %s", scorez)
        for finding in scorez:
            logger.error('finding is %s', finding)
            if finding:

                # TODO, get LOWS and sinks from the same place BasicBlock interpreter does
                LOWS = set(['self.redirect'])
                if finding['sink'] in LOWS:
                    # raise
                    issue_counts['SEVERITY.LOW'] = issue_counts['SEVERITY.LOW'] + 1

                # for (criteria, default) in constants.CRITERIA:
                #     for i, rank in enumerate(constants.RANKING):
                #         label = '{0}.{1}'.format(criteria, rank)

                #         logger.error('label is %s', label)
                #         logger.error('finding[\'sink\'] is %s', finding['sink'])



                #         # if label not in issue_counts:
                #         #     issue_counts[label] = 0

                #         #     logger.debug('criteria is %s', criteria)
                #         #     logger.debug('i is %s', i)
                #         #     logger.debug('finding is %s', finding)
                #         #     logger.debug('scores is %s', scores)

                #         #     count = (
                #         #         finding[criteria][i] /
                #         #         constants.RANKING_VALUES[rank]
                #         #     )
                #         #     issue_counts[label] += count

        logger.error('issue counts is %s', issue_counts)
        return issue_counts
