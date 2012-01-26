import time
import os, errno, sys
import re
import logging as log
import logging.handlers
import datetime
import urllib2

from utils import mq_utils, bz_utils, common
from utils.db_handler import DBHandler, PatchSet, Branch, Comment

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

if config.get('staging', False):
    import subprocess

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
    Returns the first autoland tag in the whiteboard
    """
    r = re.compile('\[autoland(-[^\[\]:]+)?((:\d+(,\d+)*)|(:-[^\[\]:]+)){0,2}\]', re.I)
    s = r.search(whiteboard)
    if s != None:
        s = s.group().lower()
    return s

def get_branch_from_tag(tag):
    """
    Returns a list of branch names from the given autoland tag.
    Given a tag that does not include '-branch',
    'try' will be returned.
    """
    r = re.compile('\[autoland-([^:\]]+)', re.I)
    s = r.search(tag)
    if s == None:
        return 'try'
    return s.groups()[0].lower()

def get_try_syntax_from_tag(tag):
    # return a string of try_syntax (must start with -)
    parts = tag.strip('[]').split(':')
    for part in parts:
        if part.startswith('-'):
            return part

def get_patches_from_tag(tag):
    # return a string of comma-delimited digits that represent attachment IDs
    patches = ''
    parts = tag.strip('[]').split(':')
    r = re.compile('^[0-9]+(,^[0-9]+)*', re.I)
    for part in parts:
        s = r.search(part.strip())
        if s != None:
            values = part.strip().split(',')
            print values
            for v in values:
                try:
                    int(v)
                except:
                    # well it's not valid then, don't include it
                    values.remove(v)
                    pass
            patches = ','.join(values)
    return patches

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
        # patches must meet criteria: is_patch and not is_obsolete
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
                        post_comment('Autoland Failure\nPatch %s requires review+ to push to branch.' % (patch['id']), bug_id)
                    return None
                for review in reviews:
                    if review['result'] != '+': # Bad review, fail
                        # comment bad review
                        if review_comment:
                            post_comment('Autoland Failure\nPatch %s has a non-passing review. Requires review+ to push to branch.' % (patch['id']), bug_id)
                        return None
                    review['reviewer'] = bz.get_user_info(review['reviewer'])
                patch['reviews'] = reviews
            patchset.append(patch)
            if patches:
                patches.remove(patch['id'])

    if len(patches) != 0:
        # comment that all requested patches didn't get applied
        # XXX TODO - should we still push what patches _did_ get applied?
        log_msg('Autoland failure. Publishing comment...', log.DEBUG)
        post_comment(('Autoland Failure\nSpecified patches %s do not exist, or are not posted on this bug.' % patches), bug_id)
        return None
    if len(patchset) == 0:
        post_comment('Autoland Failure\nThe bug has no patches posted, there is nothing to push.', bug_id)
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

        # get the branches
        branches = get_branch_from_tag(tag)
        print "Getting branches: %s" % branches
        if branches != 'try':
            goto_next = False
            for branch in branches:
                # clean out any invalid branch names
                # job will still land to any correct branches
                if db.BranchQuery(Branch(name=branch)) == None:
                    branches.remove(branch)
                    log_msg('Branch %s does not exist.' % (branch))
        # If there are no correct branch names, go to next bug
        if not branches:
            continue

        log_msg('Found and processing tag %s' % (tag), log.DEBUG)
        # get the explicitly listed patches, if any
        patch_group = get_patches_from_tag(tag) if not None else []

        # get try syntax, if any
        try_syntax = get_try_syntax_from_tag(tag)

        ps = PatchSet()
        # all runs will get a try_run by default for now
        ps.try_syntax = try_syntax
        ps.branch = branches
        ps.patches = patch_group
        ps.bug_id = bug_id

        if db.PatchSetQuery(ps) != None:
            # we already have this in the db, don't add it.
            # Remove whiteboard tag, but don't add to db and don't comment.
            log_msg('Duplicate patchset, removing whiteboard tag.', log.DEBUG)
            bz.remove_whiteboard_tag(tag.replace('[', '\[').replace(']','\]'), bug_id)
            continue

        # add try_run attribute here so that PatchSetQuery will match patchsets
        # in any stage of their lifecycle
        ps.try_run = 1

        # check patch reviews & permissions
        patches = get_patchset(ps.bug_id, ps.try_run,
                               ps.patchList(), review_comment=False)
        if patches == None:
            # do not have patches to push, kick it out of the queue
            bz.remove_whiteboard_tag(tag.replace('[', '\[').replace(']', '\]'), bug_id)
            post_comment('No valid patches attached, nothing for Autoland to do here, removing this bug from the queue.' % (patch['id']), bug_id)
            continue
        else:
            # XXX TODO - we will need to figure out how to have multiple authors
            ps.author = patches[0]['author']['email']

        # XXX TODO - let's check here if it's a dupe before inserting the patch_set
        log_msg("Inserting job: %s" % (ps))
        patchset_id = db.PatchSetInsert(ps)
        print "PatchsetID: %s" % patchset_id

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
            'patches' : [ 53432, 64512 ],
        }
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
        if 'bug_id' not in msg:
            log_msg('Bug ID not specified.')
            return
        if 'branches' not in msg:
            log_msg('Branches not specified.')
            return
        if 'patches' not in msg:
            log_msg('Patch list not specified')
            return
        if msg['try_run'] == 0:
            # XXX: Nothing to do, don't add.
            log_msg('ERROR: try_run not specified.')
            return

        if msg['branches'].lower() == ['try']:
            msg['branches'] = ['mozilla-central']
            msg['try_run'] = 1

        ps = PatchSet(bug_id=msg.get('bug_id'),
                      branch=msg.get('branch'),
                      try_run=msg.get('try_run'),
                      try_syntax=msg.get('try_syntax'),
                      patches=msg.get('patches')
                     )
        patchset_id = db.PatchSetInsert(ps)
        print "PatchSetID: %s" % patchset_id

    comment = msg.get('comment', None)
    print >>sys.stderr, "Comment: %s" % (str(comment))
    if comment:
        # Handle the posting of a comment
        bug_id = msg.get('bug_id', None)
        if not bug_id:
            log_msg('Have comment, but no bug_id')
        else:
            post_comment(comment, bug_id)

    if msg['type'] == 'success':
        if msg['action'] == 'try.push':
            # Successful push, add corresponding revision to patchset
            ps = db.PatchSetQuery(PatchSet(id=msg['patchsetid']))[0]
            print "Got patchset back from DB: %s" % ps
            print "Msg = %s" % msg
            ps.revision = msg['revision']
            db.PatchSetUpdate(ps)
            log_msg('Added revision %s to patchset %s'
                    % (ps.revision, ps.id), log.DEBUG)

        elif '.run' in msg['action']:
            # this is a result from schedulerDBpoller
            ps = db.PatchSetQuery(PatchSet(revision=msg['revision']))[0]
            # is this the try run before push to branch?
            if ps.try_run and msg['action'] == 'try.run' and ps.branch != 'try':
                # remove try_run, when it comes up in the queue it will trigger push to branch(es)
                ps.try_run = 0
                ps.push_time = None
                log_msg('Flagging patchset %s revision %s for push to branch(es).'
                        % (ps.id, ps.revision), log.DEBUG)
            else:
                # close it!
                bz.remove_whiteboard_tag('\[autoland-in-queue\]', ps.bug_id)
                db.PatchSetDelete(ps)
                log_msg('Deleting patchset %s' % (ps.id), log.DEBUG)
                return

        elif msg['action'] == 'branch.push':
            # Guaranteed patchset EOL
            ps = db.PatchSetQuery(PatchSet(id=msg['patchsetid']))[0]
            bz.remove_whiteboard_tag('\[autoland-in-queue\]', ps.bug_id)
            db.PatchSetDelete(ps)
            log_msg('Successful push to branch of patchset %s.' % (ps.id), log.DEBUG)

    elif msg['type'] == 'error' or msg['type'] == 'failure':
        ps = None
        if msg['action'] == 'try.run' or msg['action'] == 'branch.run':
            ps = db.PatchSetQuery(PatchSet(revision=msg['revision']))[0]
        elif msg['action'] == 'patchset.apply':
            ps = db.PatchSetQuery(PatchSet(id=msg['patchsetid']))[0]
        if ps:
            # remove it from the queue, error should have been comented to bug
            # (shall we confirm that here with bz_utils.has_coment?)
            bz.remove_whiteboard_tag('\[autoland-in-queue\]', ps.bug_id)
            db.PatchSetDelete(ps)
            log_msg('Received error on %s, deleting patchset %s'
                    % (msg['action'], ps.id), log.DEBUG)

def handle_patchset(patchset):
    """
    Message sent to HgPusher is of the JSON structure:
        {
          'job_type' : 'patchset',
          'bug_id' : 12345,
          'branch' : 'mozilla-central',
          'push_url' : 'ssh://hg.mozilla.org/try',
          'branch_url' : 'ssh://hg.mozilla.org/mozilla-central',
          'try_run' : 1,
          'try_syntax': '-p linux -u mochitests',
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
    log_msg('Handling patchset %s from queue.' % (patchset), log.DEBUG)

    # TODO: Check the retries & creation time.

    # Check permissions & patch set again, in case it has changed
    # since the job was put on the queue.
    patches = get_patchset(patchset.bug_id, patchset.try_run,
                           patchset.patchList())
    # get branch information so that message can contain branch_url
    branch = db.BranchQuery(Branch(name=patchset.branch))
    if not branch:
        # error, branch non-existent XXX -- SHould we email or otherwise let user know?
        log_msg('ERROR: Could not find %s in branches table.' % (patchset.branch))
        db.PatchSetDelete(patchset)
        return
    branch = branch[0]
    jobs = db.BranchRunningJobsQuery(Branch(name=patchset.branch))
    log_msg("Running jobs on %s: %s" % (patchset.branch, jobs), log.DEBUG)
    b = db.BranchQuery(Branch(name='try'))[0]
    log_msg("Threshold for %s: %s" % (patchset.branch, b.threshold), log.DEBUG)
    if jobs < b.threshold:
        message = { 'job_type':'patchset','bug_id':patchset.bug_id,
                'branch_url':branch.repo_url,
                'branch':patchset.branch, 'try_run':patchset.try_run,
                'try_syntax':patchset.try_syntax,
                'patchsetid':patchset.id, 'patches':patches }
        if patchset.try_run == 1:
            tb = db.BranchQuery(Branch(name='try'))
            if tb: tb = tb[0]
            else: return
        log_msg("SENDING MESSAGE: %s" % (message), log.INFO)
        # XXX TODO: test that message sent properly, set to retry if not
        mq.send_message(message, routing_key='hgpusher')
        patchset.push_time = datetime.datetime.utcnow()
        db.PatchSetUpdate(patchset)
    else:
        log_msg("Too many jobs running right now, will have to wait.")
        patchset.retries += 1
        db.PatchSetUpdate(patchset)

def handle_comments():
    """
    Queries the Autoland DB for any outstanding comments to be posted.
    Gets the five oldest comments and tries to post them on the corresponding
    bug. In case of failure, the comments attempt count is updated, to be
    picked up again later.
    If we have attempted 5 times, get rid of the comment and log it.
    """
    comments = db.CommentGetNext(limit=5)   # Get up to 5 comments
    for comment in comments:
        # Note that notify_bug makes multiple retries
        success = bz.notify_bug(comment.comment, comment.bug)
        if success:
            # Posted. Get rid of it.
            db.CommentDelete(comment)
        elif comment.attempts == 5:
            # 5 attempts have been made, drop this comment as it is
            # probably not going anywhere.
            # XXX: Perhaps this should be written to a file.
            print >>sys.stderr,"Could not post comment to bug %s. Dropping comment: %s" \
                    % (comment.bug, comment.comment)
            log_msg("Could not post comment to bug %s. Dropping comment: %s"
                    % (comment.bug, comment.comment))
            db.CommentDelete(comment.id)
        else:
            comment.attempts += 1
            db.CommentUpdate(comment)

def post_comment(comment, bug_id):
    """
    Post a comment that isn't in the comments db.
    Add it if posting fails.
    """
    success = bz.notify_bug(comment, bug_id)
    if success:
        log_msg('Posted comment: "%s" to %s' % (comment, bug_id))
    else:
        log_msg('Could not post comment to bug %s. Adding to comments table'
                % (bug_id))
        cmnt = Comment(comment=comment, bug=bug_id)
        db.CommentInsert(cmnt)

def main():
    mq.set_host(config['mq_host'])
    mq.set_exchange(config['mq_exchange'])
    mq.connect()

    log.basicConfig(format=LOGFORMAT, level=log.DEBUG,
            filename=LOGFILE, handler=LOGHANDLER)

    while True:
        # search bugzilla for any relevant bugs
        bz_search_handler()
        next = time.time() + int(config['bz_poll_frequency'])

        if config.get('staging', False):
            # if this is a staging instance, launch schedulerDbPoller in order
            # to poll by revision. This will allow for posting back to
            # landfill.
            for revision in db.PatchSetGetRevs():
                cmd = ['python', 'run_scheduleDbPoller_staging']
                cmd.extend(revision)
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                (out, err) = proc.communicate()
                print proc.returncode
                print out
                print err

        while time.time() < next:
            patchset = db.PatchSetGetNext()
            if patchset != None:
                handle_patchset(patchset)

            # take care of any comments that couldn't previously be posted
            handle_comments()

            # get any incoming messages
            mq.get_message(config['mq_autoland_queue'],
                    message_handler, routing_key='db')

            time.sleep(5)


if __name__ == '__main__':
    main()

