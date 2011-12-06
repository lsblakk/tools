import urllib2, re
import logging as log
import os, time, datetime
try:
    import simplejson as json
except ImportError:
    import json

class bz_util():
    def __init__(self, api_url, url, attachment_url=None, username=None, password=None):
        self.api_url = api_url
        self.url = url
        self.attachment_url = attachment_url
        self.username = username
        self.password = password

# add a check_bug so that other functions can clear that it exists before doing a request
# change return codes so that schedulerdbpoller knows when to quit - raise the exceptions up from request to all the other functions

# Catch these exceptions: 
# bug doesn't exist
# bug can't be accessed

    def request(self, path, data=None, method=None):
        """
        Request a page through the bugzilla api.
        """
        url = self.api_url + path
        if data:
            data = json.dumps(data)

        if self.username and self.password:
            if re.search('\?', path):
                url += '&'
            else:
                url += '?'
            url += 'username=%s&password=%s' % (self.username, self.password)

        req = urllib2.Request(url, data, {'Accept': 'application/json', 'Content-Type': 'application/json'})
        if method:
            req.get_method = lambda: method
        try:
            result = urllib2.urlopen(req)
            data = result.read()
            page = json.loads(data)
        except urllib2.URLError, e:
            log.error(e)
            raise
        except ValueError, e:
            log.error(e)
            raise

        return page

    def put_request(self, path, data, retries, interval):
        """
        Perform a PUT request, raise 'PutError' if can't complete.
        """
        for i in range(retries):
            # PUT the changes
            result = self.request(path, data, 'PUT')
            if 'ok' in result and result['ok'] == 1:
                return result
            time.sleep(interval)
        log.debug(result)
        raise Exception('PutError')

    def get_patch(self, patch_id, path='.', create_path=False, overwrite_patch=False):
        """
        Get a patch file from the bugzilla api. Uses the attachment url setting
        from the config file. The patch file is named {bugid}.patch .
        If create_path is True, path will be created if it does not exist.
        If overwrite_patch is True, the patch will be overwritten if it exists,
        otherwise it will not be updated, and the path will be returned.
        """
        patch_file = '%s/%s.patch' % (path, patch_id)
        if not os.access(path, os.F_OK):
            os.makedirs(path)
        if os.access(patch_file, os.F_OK) and not overwrite_patch:
            return patch_file
        try:
            d = urllib2.urlopen("%s%s" %(self.attachment_url, patch_id)).read()
        except:
            return None
        if re.search('The attachment id %s is invalid' % patch_id, d):
            return None
        f = open(patch_file, 'w')
        f.write(d)
        f.close()
        return os.path.abspath(patch_file)

    def get_user_info(self, email):
        """
        Given a user's email address, return a dict with name and email.
        """
        if not email:
            return None
        data = self.request('user/%s' % (email))
        if 'name' not in data:
            return None
        info = {}
        info['name'] = re.split('\s*\[', data['real_name'], 1)[0]
        info['email'] = data.get('email', email)
        return info

    def remove_whiteboard_tag(self, regex, bugid, retries=5, interval=10):
        """
        Remove the first whiteboard tag matching regex from the specified bug.
        By default retries 5 times at a 30s interval.
        Returns True if the regex was there to replace, and returns False if the
        regex wasn't present.
        """
        # have to compile the re in order to allow case-insensitivity in 2.6
        reg = re.compile(regex, flags=re.I)
        # get the current whiteboard tag
        bug = self.request('bug/%s?include_fields=whiteboard,last_change_time,update_token' % (bugid))
        if not 'update_token' in bug or not 'whiteboard' in bug:
            return False
        whiteboard = reg.sub('', bug['whiteboard'], 1)

        if whiteboard == bug['whiteboard']:
            return False

        data = {'token':bug['update_token'], 'whiteboard':whiteboard,
                'last_change_time' : bug['last_change_time']}
        self.put_request('bug/%s' % (bugid), data, retries, interval)
        return True

    def add_whiteboard_tag(self, tag, bugid, retries=5, interval=10):
        """
        Add tag to the specified bug.
        By default retries 5 times at a 30s interval.
        """
        bug = self.request('bug/%s?include_fields=whiteboard,last_change_time,update_token' % (bugid))
        if not 'update_token' in bug:
            # not an editable bugid
            return False
        if not 'whiteboard' in bug:
            bug['whiteboard'] = tag
        else:
            bug['whiteboard'] += tag

        data = {'token':bug['update_token'], 'whiteboard':bug['whiteboard'],
                'last_change_time' : bug['last_change_time']}
        self.put_request('bug/%s' % (bugid), data, retries, interval)
        return True

    def replace_whiteboard_tag(self, regex, replacement, bugid,
                               retries=5, interval=10):
        """
        Replace the specified regex with replacement. Returns True if the
        replacement was completed successfully.
        """
        # have to compile the re in order to allow case-insensitivity in 2.6
        reg = re.compile(regex, flags=re.I)
        # get the current whiteboard tag
        bug = self.request('bug/%s?include_fields=whiteboard,last_change_time,update_token' % (bugid))
        if not 'whiteboard' in bug:
            # In case regex is '^$' or similar, we still want to add it.
            bug['whiteboard'] = ''

        whiteboard = reg.sub(replacement, bug['whiteboard'])

        if whiteboard == bug['whiteboard']:
            return False

        data = {'token':bug['update_token'], 'whiteboard':whiteboard,
                'last_change_time' : bug['last_change_time']}
        self.put_request('bug/%s' % (bugid), data, retries, interval)
        return True

    def bugs_from_comments(self, comments):
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

    
    def check_request(self, *args, **kw):
        try:
            result = self.request(*args, **kw)
            assert not result.get('error'), result
        except urllib2.HTTPError, e:
            assert 200 <= e.code < 300, e
    
    def notify_bug(self, message, bug_num, retries=5):
        post_results = None
        for i in range(retries):
            results = 1
            log.debug("Getting bug %s", bug_num)
            try:
                # Make sure we can reach this bug
                bug = self.request("/bug/%s" % bug_num)
                log.debug("BUG: %s" % bug)
                # Add the comment
                log.debug("Adding comment to bug %s", bug_num)
                self.check_request("/bug/%s/comment" % bug_num,
                        {"text": message, "is_private": False}, "POST")
            except urllib2.HTTPError, e:
                log.debug("Couldn't get bug, retry %d of %d" % (i +1, retries))
                results = 0
                if i < retries:
                    continue
                else:
                    raise
            break
        log.debug("RESULTS: %s" % results)
        return results

    def has_comment(self, text, bugid):
        """
        Checks to see if the specified bug already has the comment text posted.
        """
        page = self.request('bug/%s/comment' % (bugid))
        if not 'comments' in page:
            # error, we shouldn't be here
            pass
        for comment in page['comments']:
            if comment['text'] == text:
                return True
        return False

    def has_recent_comment(self, regex, bugid, hours=4):
        """
        Returns true if there is a comment matching regex posted in the past
        number of hours specified.
        """
        try:
            page = self.request('bug/%s/comment?include_fields=creation_time,text'
                % (bugid))
        except urllib2.HTTPError, e:
            log.debug("Couldn't get page: %s" % e)
            return False
        if not page or not 'comments' in page:
            # error, we shouldn't be here
            return False
        current_time = datetime.datetime.utcnow()
        for comment in page['comments']:
            # May need to account for timezone
            creation_time = datetime.datetime.strptime(comment['creation_time'], '%Y-%m-%dT%H:%M:%SZ')
            if (current_time - creation_time) < datetime.timedelta(hours=hours):
                if re.search(regex, comment['text'], re.I):
                    return True
        return False

    def get_matching_bugs(self, field, match_string, match_type='regex'):
        """
        Returns bugids whose text field matches the match_string using
        match_type.
        Eg. get_matching_bugs('whiteboard', 'Autoland', 'regex')
                will return all bugs that contain the word Autoland in
                their whiteboard.
        For list of types and more information on fields, see
        https://wiki.mozilla.org/Bugzilla:REST_API:Search
        Note that for this api, the regex need not escape [] characters.
        """
        page = self.request('bug/?%s=%s&%s_type=%s&include_fields=id,%s'
                % (field, match_string, field, match_type, field))
        if not 'bugs' in page:
            # error, we shouldn't be here
            return []
        bugs = []
        for b in page['bugs']:
            bugs.append((b['id'], b[field]))
        return bugs

