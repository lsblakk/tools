import sys
from urllib2 import urlopen

from release.paths import makeCandidatesDir

def getBuildID(platform, product, version, buildNumber, nightlyDir='nightly',
               server='stage.mozilla.org', verbose=False):
    infoTxt = makeCandidatesDir(product, version, buildNumber, nightlyDir,
                                protocol='http', server=server) + \
              '%s_info.txt' % platform
    try:
        buildInfo = urlopen(infoTxt).read()
    except:
        if verbose:
            print >>sys.stderr, "Failed to retrieve %s" % infoTxt
        raise

    for line in buildInfo.splitlines():
        key,value = line.rstrip().split('=', 1)
        if key == 'buildID':
            return value

def findOldBuildIDs(product, version, buildNumber, platforms,
                    nightlyDir='nightly', server='stage.mozilla.org',
                    verbose=False):
    ids = {}
    if buildNumber <= 1:
        return ids
    for n in range(1, buildNumber):
        for platform in platforms:
            if platform not in ids:
                ids[platform] = []
            try:
                id = getBuildID(platform, product, version, n, nightlyDir,
                                server, verbose)
                ids[platform].append(id)
            except Exception, e:
                if verbose:
                    print >>sys.stderr, "Hit exception: %s" % e
    return ids