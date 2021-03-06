import site
site.addsitedir('vendor')
site.addsitedir('vendor/lib/python')

import time
import os, sys
import re
import logging
import logging.handlers
import datetime
import urllib2

from utils import mq_utils, bz_utils, common
base_dir = common.get_base_dir(__file__)
site.addsitedir('%s/../../lib/python' % (base_dir))

from utils.db_handler import DBHandler, PatchSet, Branch, Comment

log = logging.getLogger()
LOGFORMAT = logging.Formatter(
        '%(asctime)s\t%(module)s\t%(funcName)s\t%(message)s')
LOGFILE = os.path.join(base_dir, 'autoland_queue.log')
LOGHANDLER = logging.handlers.RotatingFileHandler(LOGFILE,
                    maxBytes=50000, backupCount=5)

config = common.get_configuration([os.path.join(base_dir, 'config.ini'),
                                   os.path.join(base_dir, 'secrets.ini')])
bz = bz_utils.bz_util(api_url=config['bz_api_url'], url=config['bz_url'],
        attachment_url=config['bz_attachment_url'],
        username=config['bz_username'], password=config['bz_password'])
mq = mq_utils.mq_util(host=config['mq_host'],
                      vhost=config['mq_vhost'],
                      username=config['mq_username'],
                      password=config['mq_password'],
                      exchange=config['mq_exchange'])
db = DBHandler(config['databases_autoland_db_url'])

if config.get('staging', False):
    import subprocess

def get_first_autoland_tag(whiteboard):
    """
    Returns the first autoland tag in the whiteboard
    """
    r = re.compile(r'\[autoland(-[^\[\]:]+)?((:\d+(,\d+)*)'
                   r'|(:-[^\[\]:]+)){0,2}\]', re.I)
    s = r.search(whiteboard)
    if s != None:
        s = s.group().lower()
    return s

def get_branch_from_tag(tag):
    """
    Returns a list of branch names from the given autoland tag.
    All tags must include "-branch" including try.
    eg. [autoland-try], [autoland-mozilla-central],
        [autoland-mozilla-aurora,mozilla-beta]
    """
    r = re.compile('\[autoland-([^:\]]+)', re.I)
    s = r.search(tag)
    if s == None:
        return None
    return re.split(',', s.groups()[0].lower())

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
            for v in tuple(values):
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
        for review_type in ('review', 'superreview', 'ui-review'):
            if flag.get('name') == review_type:
                reviews.append({'type':review_type,
                                'reviewer':flag['setter']['name'],
                                'result':flag['status']})
                break
    return reviews

def get_patchset(bug_id, try_run, user_patches=None, review_comment=True):
    """
    If user_patches specified, only fetch the information on those specific
    patches from the bug.
    If user_patches not specified, fetch the information on all patches from
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
    patchset = []   # hold the final patchset information
    reviews = []    # hold the review information corresponding to each patch

    # grab the bug data
    bug_data = bz.request('bug/%s' % (bug_id))
    if 'attachments' not in bug_data:
        return None     # bad bug id, or no attachments

    if user_patches:
        # user-specified patches, need to pull them in that set order
        user_patches = list(user_patches)    # take a local copy, passed by ref
        for user_patch in list(user_patches):
            for attachment in bug_data['attachments']:
                if attachment['id'] != user_patch \
                        or not attachment['is_patch'] \
                        or attachment['is_obsolete']:
                    continue
                patch = { 'id' : user_patch,
                          'author' : bz.get_user_info(
                              attachment['attacher']['name']),
                          'reviews' : [] }
                reviews.append(get_reviews(attachment))
                patchset.append(patch)
                # remove the patch from user_patches to check all listed
                # patches were pulled
                user_patches.remove(patch['id'])
        if len(user_patches) != 0:
            # not all requested patches could be picked up
            # XXX TODO - should we still push what patches _did get picked up?
            log.debug('Autoland failure. Not all user_patches could '
                      'be picked up from bug.')
            post_comment(('Autoland Failure\nSpecified patches %s '
                          'do not exist, or are not posted to this bug.'
                          % (user_patches)), bug_id)
            return None
    else:
        # no user-specified patches, grab them in the order they were posted.
        for attachment in bug_data['attachments']:
            if not attachment['is_patch'] or attachment['is_obsolete']:
                # not a valid patch to be pulled
                continue
            patch = { 'id' : attachment['id'],
                      'author' : bz.get_user_info(
                          attachment['attacher']['name']),
                      'reviews' : [] }
            reviews.append(get_reviews(attachment))
            patchset.append(patch)

    # check the reviews, based on try, etc, etc.
    for patch, revs in zip(patchset, reviews):
        if try_run:
            # on a try run, take all non-obsolete patches
            patch['reviews'] = revs
            continue

        # this is a branch push
        if not revs:
            if review_comment:
                post_comment('Autoland Failure\nPatch %s requires review+ '
                             'to push to branch.' % (patch['id']), bug_id)
                return None
        for rev in revs:
            if rev['result'] != '+':    # Bad review, fail
                if review_comment:
                    post_comment('Autoland Failure\nPatch %s has a '
                                 'non-passing review. Requires review+ '
                                 'to push to branch.'
                                 % (patch['id']), bug_id)
                return None
            rev['reviewer'] = bz.get_user_info(rev['reviewer'])
        patch['reviews'] = revs

    if len(patchset) == 0:
        post_comment('Autoland Failure\n There are no patches to run.', bug_id)
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
    except (urllib2.HTTPError, urllib2.URLError), e:
        log.error("Error while polling bugzilla: %s" % (e))
        return
    if not bugs:
        return

    for (bug_id, whiteboard) in bugs:
        tag = get_first_autoland_tag(whiteboard)
        #log.debug('Bug %s with tag %s' % (bug_id, tag))

        if tag == None or re.search('in-queue', tag) != None:
            # Strange that it showed up if None
            continue

        # get the branches
        branches = get_branch_from_tag(tag)
        log.debug('Flagged for landing on branches: %s' % (branches))
        if not branches:
            # this was probably flagged [autoland], since it was picked up
            # and doesn't have a branch attached.
            log.debug('No branches from tag %s' % (tag))
            continue
        for branch in tuple(branches):
            # clean out any invalid branch names
            # job will still land to any correct branches
            if db.BranchQuery(Branch(name=branch)) == None:
                branches.remove(branch)
                log.error('Branch %s does not exist.' % (branch))

        # If there are no correct or permissive branches, go to next bug
        if not branches:
            continue

        log.debug('Found and processing tag %s' % (tag))
        # get the explicitly listed patches, if any
        patch_group = get_patches_from_tag(tag) if not None else []

        # get try syntax, if any
        try_syntax = get_try_syntax_from_tag(tag)

        ps = PatchSet()
        # all runs will get a try_run by default for now
        ps.try_syntax = try_syntax
        ps.branch = ','.join(branches)
        ps.patches = patch_group
        ps.bug_id = bug_id

        # check patch reviews & permissions
        patches = get_patchset(ps.bug_id, ps.try_run,
                               ps.patchList(), review_comment=False)
        if not patches:
            # do not have patches to push, kick it out of the queue
            bz.remove_whiteboard_tag(tag.replace('[', '\[').replace(']', '\]'),
                    bug_id)
            log.error('No valid patches attached, nothing for '
                      'Autoland to do here, removing this bug from the queue.')
            continue
        ps.author = patches[0]['author']['email']
        ps.patches = ','.join(str(x['id']) for x in patches)

        if db.PatchSetQuery(ps) != None:
            # we already have this in the db, don't add it.
            # Remove whiteboard tag, but don't add to db and don't comment.
            log.debug('Duplicate patchset, removing whiteboard tag.')
            bz.remove_whiteboard_tag(tag.replace('[', '\[').replace(']','\]'),
                    bug_id)
            continue

        # add try_run attribute here so that PatchSetQuery will match patchsets
        # in any stage of their lifecycle
        ps.try_run = 1

        log.info('Inserting job: %s' % (ps))
        patchset_id = db.PatchSetInsert(ps)
        log.info('Insert Patchset ID: %s' % (patchset_id))

        bz.replace_whiteboard_tag('\[autoland[^\[\]]*\]',
                '[autoland-in-queue]', bug_id)


@mq.generate_callback
def message_handler(message):
    """
    Handles json messages received. Expected structures are as follows:
    For a JOB:
        {
            'type' : 'JOB',
            'bug_id' : 12345,
            'branch' : 'mozilla-central',
            'try_run' : 1,
            'patches' : [ 53432, 64512 ],
        }
    For a SUCCESS/FAILURE:
        {
            'type' : 'ERROR',
            'action' : 'PATCHSET.APPLY',
            'patchsetid' : 123,
        }
    For try run PASS/FAIL:
        {
            'type' : 'SUCCESS',
            'action' : 'TRY.RUN',
            'revision' : '8dc05498d708',
        }
    """
    msg = message['payload']
    log.info('Received message:\n%s' % (message))
    if not 'type' in msg:
        log.error('Got bad mq message: %s' % (msg))
        return
    if msg['type'] == 'JOB':
        if 'try_run' not in msg:
            msg['try_run'] = 1
        if 'bug_id' not in msg:
            log.error('Bug ID not specified.')
            return
        if 'branches' not in msg:
            log.error('Branches not specified.')
            return
        if 'patches' not in msg:
            log.error('Patch list not specified')
            return
        if msg['try_run'] == 0:
            # XXX: Nothing to do, don't add.
            log.error('ERROR: try_run not specified.')
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
        log.info('Insert PatchSet ID: %s' % (patchset_id))

    # attempt comment posting immediately, no matter the message type
    comment = msg.get('comment')
    if comment:
        # Handle the posting of a comment
        bug_id = msg.get('bug_id')
        if not bug_id:
            log.error('Have comment, but no bug_id')
        else:
            post_comment(comment, bug_id)

    if msg['type'] == 'SUCCESS':
        if msg['action'] == 'TRY.PUSH':
            # Successful push, add corresponding revision to patchset
            ps = db.PatchSetQuery(PatchSet(id=msg['patchsetid']))
            if ps == None:
                log.info('No corresponding patch set found for %s'
                        % (msg['patchsetid']))
                return
            ps = ps[0]
            log.debug('Got patchset back from DB: %s' % (ps))
            ps.revision = msg['revision']
            db.PatchSetUpdate(ps)
            log.debug('Added revision %s to patchset %s'
                    % (ps.revision, ps.id))

        elif '.RUN' in msg['action']:
            # this is a result from schedulerDBpoller
            ps = db.PatchSetQuery(PatchSet(revision=msg['revision']))
            if ps == None:
                log.error('Revision %s not found in database.'
                        % (msg['revision']))
                return
            ps = ps[0]
            # is this the try run before push to branch?
            if ps.try_run and \
                    msg['action'] == 'TRY.RUN' and ps.branch != 'try':
                # remove try_run, when it comes up in the queue
                # it will trigger push to branch(es)
                ps.try_run = 0
                ps.push_time = None
                log.debug('Flag patchset %s revision %s for push to branch.'
                        % (ps.id, ps.revision))
                db.PatchSetUpdate(ps)
            else:
                # close it!
                bz.remove_whiteboard_tag('\[autoland-in-queue\]', ps.bug_id)
                db.PatchSetDelete(ps)
                log.debug('Deleting patchset %s' % (ps.id))
                return

        elif msg['action'] == 'BRANCH.PUSH':
            # Guaranteed patchset EOL
            ps = db.PatchSetQuery(PatchSet(id=msg['patchsetid']))[0]
            bz.remove_whiteboard_tag('\[autoland-in-queue\]', ps.bug_id)
            db.PatchSetDelete(ps)
            log.debug('Successful push to branch of patchset %s.' % (ps.id))
    elif msg['type'] == 'TIMED_OUT':
        ps = None
        if msg['action'] == 'TRY.RUN':
            ps = db.PatchSetQuery(PatchSet(revision=msg['revision']))
            if ps == None:
                log.error('No corresponding patchset found for '
                          'timed out revision %s' % (msg['revision']))
                return
            ps = ps[0]
        if ps:
            # remove it from the queue, timeout should've been comented to bug
            # XXX: (shall we confirm that here with bz_utils.has_comment?)
            bz.remove_whiteboard_tag('\[autoland-in-queue\]', ps.bug_id)
            db.PatchSetDelete(ps)
            log.debug('Received time out on %s, deleting patchset %s'
                    % (msg['action'], ps.id))
    elif msg['type'] == 'ERROR' or msg['type'] == 'FAILURE':
        ps = None
        if msg['action'] == 'TRY.RUN' or msg['action'] == 'BRANCH.RUN':
            ps = db.PatchSetQuery(PatchSet(revision=msg['revision']))
            if ps == None:
                log.error('No corresponding patchset found for revision %s'
                        % (msg['revision']))
                return
            ps = ps[0]
        elif msg['action'] == 'PATCHSET.APPLY':
            ps = db.PatchSetQuery(PatchSet(id=msg['patchsetid']))
            if ps == None:
                log.error('No corresponding patchset found for revision %s'
                        % msg['revision'])
                return
            ps = ps[0]

        if ps:
            # remove it from the queue, error should have been comented to bug
            # XXX: (shall we confirm that here with bz_utils.has_coment?)
            bz.remove_whiteboard_tag('\[autoland-in-queue\]', ps.bug_id)
            db.PatchSetDelete(ps)
            log.debug('Received error on %s, deleting patchset %s'
                    % (msg['action'], ps.id))

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
    log.debug('Handling patchset %s from queue.' % (patchset))

    # TODO: Check the retries & creation time.

    # Check permissions & patch set again, in case it has changed
    # since the job was put on the queue.
    patches = get_patchset(patchset.bug_id, patchset.try_run,
                           user_patches=patchset.patchList())
    if not patches:
        log.info("Patchset not valid. Deleting from database.")
        db.PatchSetDelete(patchset)

    # get branch information so that message can contain branch_url
    branch = db.BranchQuery(Branch(name=patchset.branch))
    if not branch:
        # error, branch non-existent
        # XXX -- Should we email or otherwise let user know?
        log.error('Could not find %s in branches table.' % (patchset.branch))
        db.PatchSetDelete(patchset)
        return
    branch = branch[0]

    push_url = ''
    if patchset.try_run:
        running = db.BranchRunningJobsQuery(Branch(name='try'))
        log.debug("Running jobs on try: %s" % (running))

        # get try branch info
        try_branch = db.BranchQuery(Branch(name='try'))
        if try_branch: try_branch = try_branch[0]
        else: return

        log.debug("Threshold for try: %s" % (try_branch.threshold))

        # ensure try is not above threshold
        if running >= try_branch.threshold:
            log.info("Too many jobs running on try right now.")
            return
        push_url = try_branch.repo_url
    else:   # branch landing
        running = db.BranchRunningJobsQuery(Branch(name=patchset.branch),
                                            count_try=False)
        log.debug("Running jobs on %s: %s" % (patchset.branch, running))

        log.debug("Threshold for branch: %s" % (branch.threshold))

        # ensure branch not above threshold
        if running >= branch.threshold:
            log.info("Too many jobs landing on %s right now." % (branch.name))
            return
        push_url = branch.repo_url

    message = { 'job_type':'patchset', 'bug_id':patchset.bug_id,
            'branch_url':branch.repo_url,
            'push_url':push_url,
            'branch':patchset.branch, 'try_run':patchset.try_run,
            'try_syntax':patchset.try_syntax,
            'patchsetid':patchset.id, 'patches':patches }

    log.info("Sending job to hgpusher: %s" % (message))
    mq.send_message(message, routing_key='hgpusher')
    patchset.push_time = datetime.datetime.utcnow()
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
            try:
                with open('failed_comments.log', 'a') as fc_log:
                    fc_log.write('%s\n\t%s'
                            % (comment.bug, comment.comment))
            except IOError, err:
                log.error('Unable to append to failed comments file.')
            log.error("Could not post comment to bug %s. Dropping comment: %s"
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
        log.info('Posted comment: "%s" to %s' % (comment, bug_id))
    else:
        log.info('Could not post comment to bug %s. Adding to comments table'
                % (bug_id))
        cmnt = Comment(comment=comment, bug=bug_id)
        db.CommentInsert(cmnt)

def main():
    mq.connect()
    mq.declare_and_bind(config['mq_autoland_queue'], 'db')

    log.setLevel(logging.DEBUG)
    LOGHANDLER.setFormatter(LOGFORMAT)
    log.addHandler(LOGHANDLER)

    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            if arg == '--purge-queue':
                # purge the autoland queue
                mq.purge_queue(config['mq_autoland_queue'], prompt=True)
                exit(0)

    while True:
        # search bugzilla for any relevant bugs
        bz_search_handler()
        next_poll = time.time() + int(config['bz_poll_frequency'])

        if config.get('staging', False):
            # if this is a staging instance, launch schedulerDbPoller in order
            # to poll by revision. This will allow for posting back to
            # landfill.
            for revision in db.PatchSetGetRevs():
                cmd = ['bash', os.path.join(base_dir,
                                    'run_schedulerDbPoller_staging')]
                cmd.append(revision)
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
                (out, err) = proc.communicate()
                log.info('schedulerDbPoller Returned: %d' % (proc.returncode))
                log.info('stdout: %s' % (out))
                log.info('stderr: %s' % (err))

        while time.time() < next_poll:
            patchset = db.PatchSetGetNext()
            if patchset != None:
                handle_patchset(patchset)

            # take care of any comments that couldn't previously be posted
            handle_comments()

            # loop while we've got incoming messages
            while mq.get_message(config['mq_autoland_queue'],
                    message_handler):
                continue
            time.sleep(5)

if __name__ == '__main__':
    main()

