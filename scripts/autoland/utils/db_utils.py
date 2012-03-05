import re
import time

# Buildrequest statuses
PENDING, RUNNING, COMPLETE, CANCELLED, INTERRUPTED, MISC = range(6)

# Buildrequest results
NO_RESULT, SUCCESS, WARNINGS, FAILURE, SKIPPED, EXCEPTION, RETRY = range(-1, 6)

# Slave status
IDLE = 0
BUSY = 1
UNKNOWN = 2

BUILDPOOL_MASTERS = {
    'buildpool': [
        'production-master01.build.mozilla.org',
        'production-master03.build.mozilla.org',
        'buildbot-master1.build.scl1.mozilla.com:/builds/buildbot/build_master3',
        'buildbot-master2.build.scl1.mozilla.com:/builds/buildbot/build_master4',
    ],
    'trybuildpool': [
        'production-master02.build.mozilla.org',
    ],
    'testpool': [
        'test-master01',
        'test-master02',
        'talos-master02',
        'buildbot-master1.build.scl1.mozilla.com:/builds/buildbot/tests_master3',
        'buildbot-master1.build.scl1.mozilla.com:/builds/buildbot/tests_master4',
        'buildbot-master2.build.scl1.mozilla.com:/builds/buildbot/tests_master5',
        'buildbot-master2.build.scl1.mozilla.com:/builds/buildbot/tests_master6',
    ],
}

PLATFORMS_BUILDERNAME = {
    'linux': [
        re.compile('^Linux (?!x86-64).+'),
        re.compile('.*linux(?!64).*'),
        re.compile('^Maemo 4 .+'),
        re.compile('^Maemo 5 QT .+'),
        re.compile('^Maemo 5 GTK .+'),
        re.compile('^Android R7 .+'),
    ],
    'linux64': [
        re.compile('^Linux x86-64 .+'),
        re.compile('.*linux64.*'),
    ],
    'fedora': [
        re.compile('^Rev3 Fedora 12 .+'),
    ],
    'fedora64': [
        re.compile('Rev3 Fedora 12x64 .+'),
    ],
    'leopard': [
        re.compile('^OS X 10\.5.+'),
        re.compile('^Rev3 MacOSX Leopard 10\.5.+'),
        re.compile('.*macosx(?!64).*'),
    ],
    'snowleopard': [
        re.compile('^OS X 10\.6.+'),
        re.compile('^Rev3 MacOSX Snow Leopard 10\.6.+'),
        re.compile('.*macosx64.*'),
    ],
    'xp': [
        re.compile('^Rev3 WINNT 5\.1 .+')
    ],
    'win2k3': [
        re.compile('^WINNT 5\.2 .+'),
        re.compile('.*win32.*'),
    ],
    'win7': [
        re.compile('^Rev3 WINNT 6\.1 '),
    ],
    'win764': [
        re.compile('^Rev3 WINNT 6\.1 x64 .+'),
    ],
}

BUILD_TYPE_BUILDERNAME = {
    'opt': [
        re.compile('.+ opt .+'),
        re.compile('.+(?<!leak test) build'),
        re.compile('.+ talos .+'),          # all talos are made only for opt
        re.compile('.+ nightly$'),          # all nigtly builds are opt
        re.compile('.+ xulrunner$'),        # nightly
        re.compile('.+ shark$'),            # nightly
        re.compile('.+ code coverage$'),    # nightly
    ],
    'debug': [
        re.compile('.+ debug .+'),
        re.compile('.+ leak test build'),
    ],
}

JOB_TYPE_BUILDERNAME = {
    'build': [
        re.compile('.+ build'),
        re.compile('.+(?<!l10n) nightly$'),     # all 'nightly'-s are builds
        re.compile('.+ xulrunner$'),            # nightly
        re.compile('.+ shark$'),                # nightly
        re.compile('.+ code coverage$'),        # nightly
    ],
    'unittest': [ re.compile('.+(?<!leak) test .+') ],
    'talos': [ re.compile('.+ talos .+') ],
    'repack': [ re.compile ('.+ l10n .+') ],
}

SOURCESTAMPS_BRANCH = {
    'l10n-central': [re.compile('^l10n-central.*')],
    'birch': [re.compile('^birch.+'), re.compile('^projects/birch.*')],
    'cedar': [re.compile('^cedar.+'), re.compile('^projects/cedar.*')],
    'electrolysis': [
        re.compile('^electrolysis.*'),
        re.compile('^projects/electrolysis.*')],
    'jaegermonkey': [re.compile('^projects/jaegermonkey.*')],
    'maple': [re.compile('^maple.*'), re.compile('^projects/maple.*')],
    'mozilla-1.9.1': [re.compile('.*mozilla-1\.9\.1.*')],
    'mozilla-1.9.2': [re.compile('.*mozilla-1\.9\.2.*')],
    'mozilla-2.0': [re.compile('.*mozilla-2\.0.*')],
    'mozilla-central': [re.compile('^mozilla-central.*')],
    'places': [re.compile('^places.+'), re.compile('^projects/places.*')],
    'nanojit-central': [re.compile('.*nanojit-central.*')],
    'tracemonkey': [re.compile('^tracemonkey.*')],
    'try': [re.compile('^try$'), re.compile('^tryserver.*')],
}

SLAVE_SILOS = {
    'bm-xserve': [re.compile('^bm-xserve.+')],
    'linux-ix': [re.compile('^linux-ix-slave.+')],
    'moz2-darwin10': [re.compile('^moz2-darwin10-slave.+')],
    'moz2-darwin9': [re.compile('^moz2-darwin9-slave.+')],
    'moz2-linux': [re.compile('^moz2-linux-slave.+')],
    'moz2-linux64': [re.compile('^moz2-linux64-slave.+')],
    'moz2-win32': [re.compile('^moz2-win32-slave.+')],
    'mv-moz2-linux-ix': [re.compile('^mv-moz2-linux-ix-slave.+')],
    'mw32-ix': [re.compile('^mw32-ix-slave.+')],
    't-r3-w764': [re.compile('^t-r3-w764-.+')],
    'talos-r3-fed': [re.compile('^talos-r3-fed-.+')],
    'talos-r3-fed64': [re.compile('^talos-r3-fed64-.+')],
    'talos-r3-leopard': [re.compile('^talos-r3-leopard-.+')],
    'talos-r3-snow': [re.compile('^talos-r3-snow-.+')],
    'talos-r3-w7': [re.compile('^talos-r3-w7-.+')],
    'talos-r3-xp': [re.compile('^talos-r3-xp-.+')],
    'tegra': [re.compile('^tegra-.+')],
    'try-linux': [re.compile('^try-linux-slave.+')],
    'try-linux64': [re.compile('^try-linux64-slave.+')],
    'try-mac': [re.compile('^try-mac-slave.+')],
    'try-mac64': [re.compile('^try-mac64-slave.+')],
    'try-w32': [re.compile('^try-w32-slave.+')],
    'w32-ix': [re.compile('^w32-ix-slave.+')],
    'win32': [re.compile('^win32-slave.+')],
}

BUILDERS_DETAIL_LEVELS = ['branch', 'platform', 'build_type', 'job_type',
    'builder']

BUILDSET_REASON = {
    'forcebuild':
        re.compile("The web-page 'force build' button was pressed by .+"),
    'rebuild':
        re.compile("The web-page 'rebuild' button was pressed by .+"),
}

"""
Pushes Report Configs
"""
PUSHES_SOURCESTAMPS_BRANCH_SQL_EXCLUDE = [
    '%unittest',
    '%talos',
    'addontester%',
    '%l10n%',
]

"""
Wait Times Report Configs
"""
WAITTIMES_BUILDREQUESTS_BUILDERNAME_SQL_EXCLUDE = [
    'fuzzer-%',
    'Android Tegra 250 %',
    'nanojit-%',
    'release-%',
    'valgrind%',
]

WAITTIMES_BUILDSET_REASON_SQL_EXCLUDE = [
    "The web-page 'force build' button was pressed by %",
    "The web-page 'rebuild' button was pressed by %",
]

WAITTIMES_BUILDREQUESTS_BUILDERNAME_EXCLUDE = [
    re.compile('.+ l10n .+'),
]

_STATUS_TO_STR = {
    PENDING: 'PENDING',
    RUNNING: 'RUNNING',
    COMPLETE: 'COMPLETE',
    CANCELLED: 'CANCELLED',
    INTERRUPTED: 'INTERRUPTED',
    MISC: 'MISC',
}

_RESULTS_TO_STR = {
    NO_RESULT: '-',
    SUCCESS: 'success',
    WARNINGS: 'warnings',
    FAILURE: 'failure',
    SKIPPED: 'skipped',
    EXCEPTION: 'exception',
    RETRY: 'retry',
}

def status_to_str(status):
    """Return the status as string.

    Input:  status - status int value, one of: PENDING, RUNNING, COMPLETE,
                CANCELLED, INTERRUPTED, MISC
    Output: status string representation
    """
    if status not in _STATUS_TO_STR:
        status = MISC
    return _STATUS_TO_STR[status]

def results_to_str(results):
    """Return the results as string.

    Input:  results - results int value, one of: NO_RESULT, SUCCESS, WARNINGS, 
                FAILURE, SKIPPED, EXCEPTION, RETRY
    Output: results string representation
    """
    if results not in _RESULTS_TO_STR:
        results = NO_RESULT
    return _RESULTS_TO_STR[results]

def get_branch_name(text):
    """Returns the branch name.

    Input:  text - field value from schedulerdb table
    Output: branch (one in SOURCESTAMPS_BRANCH keys: mozilla-central,
            mozilla-1.9.1, or text if not found
    """
    if text == None:
        return None

    text = text.lower()
    for branch in SOURCESTAMPS_BRANCH:
        for pat in SOURCESTAMPS_BRANCH[branch]:
            if pat.match(text):
                return branch

    return text

def get_platform(buildername):
    """Returns the platform name for a buildername.

    Input:  buildername - buildername field value from buildrequests
                schedulerdb table
    Output: platform (one in PLATFORMS_BUILDERNAME keys: linux, linux64, ...)
    """
    if buildername == None:
        return None

    for platform in PLATFORMS_BUILDERNAME:
        for pat in PLATFORMS_BUILDERNAME[platform]:
            if pat.match(buildername):
                return platform

    return 'other'

def get_build_type(buildername):
    """Returns the build type based on the buildername.

    Build requests are matched to a build type, as following:
    * opt, if buildername contains 'opt', 'build' not preceded by 'leak test',
         'talos' (all talos tests are for opt), 'nightly', 'xulrunner' or
         'shark' (last 3 are all nightlies)
    * debug, if buildername contains 'debug' or 'leak test build' (debug build)

    Input:  buildername - buildername field value from buildrequests
                schedulerdb table
    Output: build type (one in BUILD_TYPE_BUILDERNAME keys: opt or debug)
    """
    if buildername == None:
        return None

    for build_type in BUILD_TYPE_BUILDERNAME:
        for pat in BUILD_TYPE_BUILDERNAME[build_type]:
            if pat.match(buildername):
                return build_type

    return None

def get_job_type(buildername):
    """Returns the job type based on the buildername.

    Build requests are matched to a job type, as following:
    * build, if buildername contains 'build', 'nightly', 'xulrunner' or
        'shark' (last 3 are all nightlies)
    * unittest, if buildername contains 'test', but not preceded by 'leak'
        (it would make it a build)
    * talos, if buildername contains 'talos'

    Input:  buildername - buildername field value from buildrequests
                schedulerdb table
    Output: job type (one in JOB_TYPE_BUILDERNAME keys: build,
            unittest or talos)
    """
    if buildername == None:
        return None

    for job_type in JOB_TYPE_BUILDERNAME:
        for pat in JOB_TYPE_BUILDERNAME[job_type]:
            if pat.match(buildername):
                return job_type

    return None

def get_revision(revision):
    """Returns at most the first 12 characters of the revision number, the
    rest are not signifiant, or None, if revision is None.
    """
    return revision[:12] if revision else revision

def get_silos(slave_name):
    """Returns the silos name based on the slave name."""
    if slave_name == None:
        return None

    for silos_name in SLAVE_SILOS:
        for pat in SLAVE_SILOS[silos_name]:
            if pat.match(slave_name):
                return silos_name

    return None

def get_time_interval(starttime, endtime):
    """Returns (sarttime2, endtime2) tuple, where the starttime2 is the exact
    value of input parameter starttime if specified, or endtime minus 24 hours
    if not. endtime2 is the exact value of input parameter endtime if
    specified, or starttime plus 24 hours or current time (if starttime is not 
    specified either).

    Input: stattime - start time (UNIX timestamp in seconds)
           endtime - end time (UNIX timestamp in seconds)
    Output: (stattime2, endtime2)
    """
    nowtime = time.time()
    if not endtime:
        endtime = min(starttime + 24 * 3600 if starttime else nowtime, nowtime)
    if not starttime:
        starttime = endtime - 24 * 3600

    return starttime, endtime
