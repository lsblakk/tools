import urllib2, re
import logging as log
try:
    import simplejson as json
except ImportError:
    import json

def bugs_from_comments(comments):
    """Finds things that look like bugs in comments and returns as a list of bug numbers.

    Supported formats:
        Bug XXXXX
        Bugs XXXXXX, YYYYY
        bXXXXX
    """
    retval = []
    # TODO - add word boundary in front and behind the bug number
    # Add test cases for this (remove the 9000)
    m = re.search(r"\bb(?:ug(?:s)?)?\s*((?:\d+[, ]*)+)", comments, re.I)
    if m:
        for m in re.findall("\d+", m.group(1)):
            # diminish the odds of getting a false bug number from an hg cset
            if int(m) > 9000:
                retval.append(int(m))
    return retval

def bz_request(api, path, data=None, method=None, username=None, password=None):
    url = api + path
    if data:
        data = json.dumps(data)

    if username and password:
        url += "?username=%s&password=%s" % (username, password)

    req = urllib2.Request(url, data, {'Accept': 'application/json', 'Content-Type': 'application/json'})
    if method:
        req.get_method = lambda: method

    result = urllib2.urlopen(req)
    data = result.read()
    return json.loads(data)

def bz_check_request(*args, **kw):
    try:
        result = bz_request(*args, **kw)
        assert not result.get('error'), result
    except urllib2.HTTPError, e:
        assert 200 <= e.code < 300, e

def bz_notify_bug(api, bug_num, message, username, password, whiteboard="", retries=5):
    for i in range(retries):
        results = 1
        log.debug("Getting bug %s", bug_num)
        try:
            bug = bz_request(api, "/bug/%s" % bug_num, username=username, password=password)
            wb = bug.get('whiteboard', '')

            if whiteboard not in wb:
                bug['whiteboard'] = wb + whiteboard
                if i == 0:
                    bug['last_change_time'] = "2009-09-09T16:31:18Z"

                # Add the whiteboard
                try:
                    log.debug("Adding whiteboard status to bug %s", bug_num)
                    bz_check_request(api, "/bug/%s" % bug_num, bug, "PUT", username=username, password=password)
                except KeyboardInterrupt:
                    raise
                except:
                    log.exception("Problem changing whiteboard, trying again")
                    if i < retries:
                        continue
                    else:
                        results = 0

            # Add the comment
            log.debug("Adding comment to bug %s", bug_num)
            bz_check_request(api, "/bug/%s/comment" % bug_num,
                    {"text": message, "is_private": False}, "POST",
                    username=username, password=password)
        except urllib2.HTTPError, e:
            log.debug("Couldn't get bug, retry %d of %d" % (i +1, retries))
            results = 0
            if i < retries:
                continue
            else:
                raise 
        break
    return results
