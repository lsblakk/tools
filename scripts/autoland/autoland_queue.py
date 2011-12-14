import time
import os, errno, sys
import re
import threading
import logging as log
import logging.handlers
import datetime
import urllib2

from utils import mq_utils, bz_utils, common
from utils.db_handler import DBHandler, PatchSet, Branch

base_dir = common.get_base_dir(__file__)

LOGFORMAT = '%(asctime)s\t%(module)s\t%(funcName)s\t%(message)s'
LOGFILE = os.path.join(base_dir, 'autoland_queue.log')
LOGHANDLER = log.handlers.RotatingFileHandler(LOGFILE,
                    maxBytes=50000, backupCount=5)

config = common.get_configuration(os.path.join(base_dir, 'config.ini'))
config.update(common.get_configuration(os.path.join(base_dir, 'auth.ini')))
bz = bz_utils.bz_util(api_url=config['bz_api_url'], url=config['bz_url'], 
        attachment_url=config['bz_attachment_url'],
        username=config['bz_username'], password=config['bz_password'])
mq = mq_utils.mq_util()
db = DBHandler(config['databases_autoland_db_url'])

def log_msg(message, log_to=log.error):
    """
    Log a message to stderr and to the given logging level.
    Pass None to log_to if the message should not be sent to log.
    """
    print >>sys.stderr, message
    if callable(log_to):
        log_to(message)

def get_first_autoland_tag(whiteboard):
    """
    Returns the first autoland tag in the whiteboard,
    need not be well-formed.
    """
    r = re.compile('\[autoland[^\[\]]*\]', re.I)
    s = r.search(whiteboard)
    if s != None:
        s = s.group().lower()
    return s

def valid_autoland_tag(tag):
    r = re.compile('\[autoland(-[^\[\]]+)?(:\d+(,\d+)*)?\]', re.I)
    return r.search(tag) != None

def get_branch_from_tag(tag):
    """
    Returns the branch name from the given autoland tag.
    Given a tag that does not include '-branch',
    'try' will be returned.
    """
    r = re.compile('\[autoland-([^:\]]+)', re.I)
    s = r.search(tag)
    if s == None:
        return 'try'
    return s.groups()[0].lower()

def get_reviews(attachment):
    """
    Takes attachment JSON, returns a list of reviews.
    Each review (in the list) is a dictionary containing:
        - Review type (review, superreview, ui-review)
        - Reviewer
        - Review Result (+, -, ?)
    """
    reviews = []
    if not 'flags' in attachment:
        return reviews
    for flag in attachment['flags']:
        for review_type in ['review', 'superreview', 'ui-review']:
            if flag.get('name') == review_type:
                reviews.append({'type':review_type,
                                'reviewer':flag['setter']['name'],
                                'result':flag['status']})
                break
    return reviews

def get_patchset(bug_id, try_run, patches=[], review_comment=True):
    """
    If patches specified, only fetch the information on those specific
    patches from the bug.
    If patches not specified, fetch the information on all patches from
    the bug.

    Try runs will contain all non-obsolete patches posted on the bug, no
    matter the state of the reviews. This means that it will take even
    patches that are R- but non-obsolete.

    Pushes to branch will contain all patches that are posted to the bug
    which have R+ on any R that is set. If there are any non-obsolete
    bugs that have R-, the push will fail since the bug may not be
    complete.

    The review_comment parameter defaults to True, and is used to specify
    if a comment should be posted on review failures on not. This has a
    somewhat specific use case:
        When checking if a flagged job should be picked up and put into the
        queue, no comment should be posted if there are missing/bad reviews.

    Return value is of the JSON structure:
        [
            { 'id' : 54321,
              'author' : { 'name' : 'Name',
                           'email' : 'me@email.com' },
              'reviews' : [
                    { 'reviewer' : { 'name' : 'Rev. Name',
                                     'email' : 'rev@email.com' },
                      'type' : 'superreview',
                      'result' : '+'
                    },
                    { ... }
                ]
            },
            { ... }
        ]
    """
    patchset = []
    if patches: patches = patches[:]    # take a local copy of patches.
    # grab the bug data
    bug_data = bz.request('bug/%s' % str(bug_id))
    if 'attachments' not in bug_data:
        return None     # bad bug id, or no attachments
    for attachment in bug_data['attachments']:
        # if it is a patch (is_patch), and is not (is_obsolete)
        if attachment['is_patch'] and not attachment['is_obsolete'] \
                and (not patches or int(attachment['id']) in patches):
            patch = {'id':int(attachment['id']),
                     'author':bz.get_user_info(attachment['attacher']['name']),
                     'reviews':[]}

            reviews = get_reviews(attachment)
            if try_run:
                # review info doesn't matter for try runs,
                # but get it anyways so we can fill the db
                patch['reviews'] = reviews
            else:   # push to branch
                if not reviews: # No reviews, fail
                    # comment that no reviews on patch x
                    if review_comment:
                        bz.notify_bug('Autoland Failure\nPatch %s requires review+ to push to branch.' % (patch['id']), bug_id)
                    return None
                for review in reviews:
                    if review['result'] != '+': # Bad review, fail
                        # comment bad review
                        if review_comment:
                            bz.notify_bug('Autoland Failure\nPatch %s has a non-passing review. Requires review+ to push to branch.' % (patch['id']), bug_id)
                        return None
                    review['reviewer'] = bz.get_user_info(review['reviewer'])
                patch['reviews'] = reviews
            patchset.append(patch)
            if patches:
                patches.remove(patch['id'])

    if len(patches) != 0:
        # Some specified patches left over
        # comment that it couldn't get all specified patches
        log_msg('Autoland failure. Publishing comment...', log.DEBUG)
        c = bz.notify_bug('Autoland Failure\nSpecified patches %s do not exist, or are not posted on this bug.' % (', '.join(map(lambda x : str(x), patches))), bug_id)
        if c:
            log_msg('Comment publised to bug %s' % (bug_id), log.DEBUG)
        else:
            log_msg('ERROR: Could not comment to bug %s' % (bug_id))
        return None
    if len(patchset) == 0:
        c = bz.notify_bug('Autoland Failure\nThe bug has no patches posted, there is nothing to push.', bug_id)
        if c:
            log_msg('Comment published to bug %s' % (bug_id), log.DEBUG)
        else:
            log_msg('ERROR: Could not comment to bug %s' % (bug_id))
        return None
    return patchset

def bz_search_handler():
    """
    Search bugzilla whiteboards for Autoland jobs.
    Search handler, for the moment, only supports push to try,
    and then to branch. It cannot push directly to branch.
    """
    bugs = []
    try:
        bugs = bz.get_matching_bugs('whiteboard', '\[autoland.*\]')
    except urllib2.HTTPError, e:
        log_msg("Error while polling bugzilla: %s" % (e))

    for (bug_id, whiteboard) in bugs:
        tag = get_first_autoland_tag(whiteboard)
        print bug_id, tag

        if tag == None or re.search('in-queue', tag) != None:
            # Strange that it showed up if None
            continue
        elif not valid_autoland_tag(tag):
            bz.notify_bug('Poorly formed whiteboard tag %s.' %(tag))
            log_msg('Poorly formed whiteboard tag %s. Comment posted.' % (tag))
            bz.remove_whiteboard_tag(tag, bug_id)
            continue
        branch = get_branch_from_tag(tag)
        if db.BranchQuery(Branch(name=branch)) == None:
            bz.notify_bug('Bad autoland tag: branch %s does not exist.' % (branch))
            log_msg('Bad autoland tag: branch %s does not exist.' % (branch))
            bz.remove_whiteboard_tag(tag, bug_id)
            continue

        log_msg('Found and processing tag %s' % (tag), log.DEBUG)
        # get the explicitly listed patches
        patch_group = []
        r = re.compile('\d+')
        for id in r.finditer(whiteboard):
            patch_group.append(int(id.group()))

        ps = PatchSet()
        if branch == 'try':
            ps.try_run = 1
            ps.to_branch = 0
            ps.branch = 'mozilla-central'
        else:
            ps.try_run = 1      # try run first
            ps.to_branch = 1    # then land to branch
            ps.branch = branch
        ps.patches = patch_group
        ps.bug_id = bug_id

        # check patch reviews & permissions
        patches = get_patchset(ps.bug_id, ps.try_run,
                               ps.patchList(), review_comment=False)
        if patches == None:
            # do not have all the necessary permissions, let the job
            # sit in Bugzilla so it can be picked up again later.
            continue

        log_msg("Inserting job: %s" % (ps))
        patchset_id = db.PatchSetInsert(ps)

        bz.replace_whiteboard_tag('\[autoland[^\[\]]*\]',
                '[autoland-in-queue]', bug_id)


def message_handler(message):
    """
    Handles json messages received. Expected structures are as follows:
    For a JOB:
        {
            'type' : 'job',
            'bug_id' : 12345,
            'branch' : 'mozilla-central',
            'try_run' : 1,
            'to_branch' : 0,
            'patches' : [ 53432, 64512 ],
        }
        NOTE: Try run specifies whether or not this should be run on try,
        whether to_branch is specified or not.
              If try_run and to_branch are both 0, job won't be added to queue.
    For a SUCCESS/FAILURE:
        {
            'type' : 'error',
            'action' : 'patchset.apply',
            'patchsetid' : 123,
        }
    For try run PASS/FAIL:
        {
            'type' : 'success',
            'action' : 'try.run',
            'revision' : '8dc05498d708',
        }
    """
    msg = message['payload']
    if not 'type' in msg:
        log_msg('Got bad mq message: %s' % (msg))
        return
    if msg['type'] == 'job':
        if 'try_run' not in msg:
            msg['try_run'] = 1
        if 'to_branch' not in msg:
            msg['to_branch'] = 0
        if 'bug_id' not in msg:
            log_msg('Bug ID not specified.')
            return
        if 'branch' not in msg:
            log_msg('Branch not specified.')
            return
        if 'patches' not in msg:
            log_msg('Patch list not specified')
            return
        if msg['try_run'] == 0 and msg['to_branch'] == 0:
            # XXX: Nothing to do, don't add.
            log_msg('ERROR: Neither try_run nor to_branch specified.')
            return

        if msg['branch'].lower() == 'try':
            msg['branch'] = 'mozilla-central'
            msg['try_run'] = 1

        ps = PatchSet(bug_id=msg.get('bug_id'),
                      branch=msg.get('branch'),
                      try_run=msg.get('try_run'),
                      to_branch=msg.get('to_branch'),
                      patches=msg.get('patches')
                     )
        patchset_id = db.PatchSetInsert(ps)

    elif msg['type'] == 'success':
        if msg['action'] == 'try.push':
            # Successful push, add corresponding revision to patchset
            ps = db.PatchSetQuery(PatchSet(id=msg['patchsetid']))[0]
            ps.revision = msg['revision']
            db.PatchSetUpdate(ps)
            log_msg('Added revision %s to patchset %s'
                    % (ps.revision, ps.id), log.DEBUG)
        elif msg['action'] == 'try.run':
            # Handle a successful try result
            ps = db.PatchSetQuery(PatchSet(revision=msg['revision']))
            if not ps:
                # XXX: wtf...
                log_msg('ERROR: Unable find revision in db.'
                        % (msg['revision']))
                return
            # Remove the -in-queue whiteboard tag
            bz.remove_whiteboard_tag('\[autoland-in-queue\]', ps.bug_id)
            # Update the one in the queue, to contain the new data we want
            # in order to be picked up and kick off the landing
            if ps.to_branch == 0:
                db.PatchSetDelete(ps)
                log_msg('Deleting patchset %s' % (ps.id), log.DEBUG)
                return
            # update to no longer be a try run, and will kick off a to_branch
            # landing when it comes up in the queue
            ps.try_run = 0
            ps.push_time = None
            db.PatchSetUpdate(ps)
            log_msg('Flagging patchset %s revision %s for push-to_branch.'
                    % (ps.id, ps.revision), log.DEBUG)
        elif msg['action'] == 'branch.push':
            # Guaranteed patchset EOL
            ps = db.PatchSetQuery(PatchSet(id=msg['patchsetid']))
            bz.remove_whiteboard_tag('\[autoland-in-queue\]', ps.bug_id)
            db.PatchSetDelete(ps)
            log_msg('Successful push to branch of patchset %s.' % (ps.id), log.DEBUG)

    elif msg['type'] == 'error' or msg['type'] == 'failure':
        ps = None
        if msg['action'] == 'try.push' or msg['action'] == 'branch.push':
            ps = db.PatchSetQuery(PatchSet(id=msg['patchsetid']))
        elif msg['action'] == 'try.run':
            ps = db.PatchSetQuery(PatchSet(revision=msg['revision']))
        elif msg['action'] == 'patchset.apply':
            ps = db.PatchSetQuery(PatchSet(id=msg['patchsetid']))
        if ps:
            bz.remove_whiteboard_tag('\[autoland-in-queue\]', ps.bug_id)
            db.PatchSetDelete(ps)
            log_msg('Received error on %s, deleting patchset %s'
                    % (msg['action'], ps.id), log.DEBUG)

class MessageThread(threading.Thread):
    """Threaded message listener"""
    def run(self):
        mq.listen(config['mq_queue'], message_handler, routing_keys=[config['mq_db_topic']])

class SearchThread(threading.Thread):
    """
    Threaded bugzilla search, also handles the jobs coming through the queue.

    Message sent to HgPusher is of the JSON structure:
        {
          'job_type' : 'patchset',
          'bug_id' : 12345,
          'branch' : 'mozilla-central',
          'push_url' : 'ssh://hg.mozilla.org/try',
          'branch_url' : 'ssh://hg.mozilla.org/mozilla-central',
          'try_run' : 1,
          'patchsetid' : 42L,
          'patches' :
                [
                    { 'id' : 54321,
                      'author' : { 'name' : 'Name',
                                   'email' : 'me@email.com' },
                      'reviews' : [
                            { 'reviewer' : { 'name' : 'Rev. Name',
                                             'email' : 'rev@email.com' },
                              'type' : 'superreview',
                              'result' : '+'
                            },
                            { ... }
                        ]
                    },
                    { ... }
                ]
        }
    """
    def run(self):
        while(1):
            # check if bugzilla has any requested jobs
            bz_search_handler()
            next = time.time() + int(config['bz_poll_frequency'])
            while time.time() < next:
                patchset = db.PatchSetGetNext()
                if patchset == None:
                        time.sleep(10)
                        continue
                log_msg('Pulled patchset %s out of the queue' % (patchset),
                        log.DEBUG)
                # Check permissions & patch set again, in case it has changed
                # since the job was put on the queue
                patches = get_patchset(patchset.bug_id, patchset.try_run,
                                       patchset.patchList())
                # get branch information so that message can contain branch_url
                branch = db.BranchQuery(Branch(name=patchset.branch))
                if not branch:
                    # error, branch non-existent
                    log_msg('ERROR: Could not find %s in branches table.' % (patchset.branch))
                    db.PatchSetDelete(patchset)
                    continue
                branch = branch[0]
                print branch
                message = { 'job_type':'patchset','bug_id':patchset.bug_id,
                        'branch_url':branch.repo_url,
                        'branch':patchset.branch, 'try_run':patchset.try_run,
                        'patchsetid':patchset.id, 'patches':patches }
                if patchset.try_run == 1:
                    tb = db.BranchQuery(Branch(name='try'))
                    if tb: tb = tb[0]
                    else: continue
                    message['push_url'] = tb.repo_url
                log_msg("SENDING MESSAGE: %s" % (message), log.INFO)
                mq.send_message(message, config['mq_queue'],
                        routing_keys=[config['mq_hgpusher_topic']])
                patchset.push_time = datetime.datetime.utcnow()
                db.PatchSetUpdate(patchset)
                time.sleep(10)

def main():
    mq.set_host(config['mq_host'])
    mq.set_exchange(config['mq_exchange'])

    log.basicConfig(format=LOGFORMAT, level=log.DEBUG,
            filename=LOGFILE, handler=LOGHANDLER)

    th_messages = MessageThread(name='messaging')
    th_search = SearchThread(name='search')
    th_messages.start()
    th_search.start()

    while th_messages.is_alive() and th_search.is_alive():
        time.sleep(10)
    if not th_messages.is_alive():
        print "Messaging thread died."
        exit(1)
    elif not th_search.is_alive():
        print "Bugzilla searching thread died."
        exit(1)
    exit(0)

if __name__ == '__main__':
    main()

