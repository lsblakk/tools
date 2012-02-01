import os, sys
import re
import subprocess
import logging as log
import logging.handlers
import shutil
from tempfile import mkdtemp
from mercurial import error, lock   # For lockfile on working dirs

from util.hg import mercurial, apply_and_push, cleanOutgoingRevs, out, \
                    remove_path, HgUtilError, update, get_revision
from util.retry import retry
from utils import bz_utils, mq_utils, common, ldap_utils

base_dir = common.get_base_dir(__file__)

LOGFORMAT = '%(asctime)s\t%(module)s\t%(funcName)s\t%(message)s'
LOGFILE = os.path.join(base_dir, 'hgpusher.log')
LOGHANDLER = log.handlers.RotatingFileHandler(LOGFILE,
                    maxBytes=50000, backupCount=5)
mq = mq_utils.mq_util()

config = common.get_configuration(os.path.join(base_dir, 'config.ini'))
config.update(common.get_configuration(os.path.join(base_dir, 'auth.ini')))
bz = bz_utils.bz_util(api_url=config['bz_api_url'], url=config['bz_url'], 
        attachment_url=config['bz_attachment_url'],
        username=config['bz_username'], password=config['bz_password'])
ldap = ldap_utils.ldap_util(config['ldap_host'], int(config['ldap_port']),
        config['ldap_bind_dn'], config['ldap_password'])

def run_hg(hg_args):
    """
    Run hg with given args, returning a tuple containing stdout,
    stderr and return code.
    """
    cmd = ['hg']
    cmd.extend(hg_args)
    proc = subprocess.Popen(cmd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (out, err) = proc.communicate()
    rc = proc.returncode
    return (out, err, rc)

def log_msg(message, log_to=log.error):
    """
    Log a message to stderr and to the given logging level.
    Pass None to log_to if the message should not be sent to log.
    """
    print >>sys.stderr, message
    if callable(log_to):
        log_to(message)

def has_valid_header(filename):
    """
    Check to see if the file has a valid header. The header must
    include author name and commit message. The commit message must
    start with 'bug \d+:'

    Note: this forces developers to use 'hg export' rather than 'hg diff'
          if they want to be pushing to branch.
    """
    f = open(filename, 'r')
    for line in f:
        if re.match('# User ', line):
            # User line must be of the form
            # # User Name <name@email.com>
            if not re.match('# User [\w\s]+ <[\w\d._%+-]+@[\w\d.-]+\.\w{2,6}>$', line):
                print 'Bad header.'
                return False
        elif re.match('^bug\s?(\d+|\w+)[:\s]', line, re.I):   # comment line
            return True
        elif re.match('^$', line):
            # done with header
            break
    return False

def in_ldap_group(email, group):
    """
    Checks ldap if either email or the bz_email are a member of the group.
    """
    bz_email = ldap.get_bz_email(email)
    return ldap.is_member_of_group(email, group) \
            or (bz_email and ldap.is_member_of_group(bz_email, group))

def has_sufficient_permissions(patches, branch):
    """
    Searches LDAP to see if any of the users (author, reviewers) have
    sufficient LDAP permissions.
    These permissions are done on a whole for the patchset, so
    if any patch is missing those permissions the whole patchset
    cannot be pushed.
    """
    group = ldap.get_branch_permissions(branch)
    if group == None:
        return False

    for patch in patches:
        found = False
        if in_ldap_group(patch['author']['email'], group):
            continue    # next patch
        for review in patch.get('reviews'):
            if not review.get('reviewer'):
                continue
            if in_ldap_group(review['reviewer'], group):
                found = True
                break   # next patch
        if not found:
            return False

    return True

def import_patch(repo, patch, try_run, bug_id=None, user=None,
        try_syntax="-p win32 -b o -u none"):
    """
    Import patch file patch into repo.
    If it is a try run, replace commit message with "try:"

    Import is used to pull required header information, and to
    automatically perform a commit for each patch
    """
    cmd = ['import', '-R']
    cmd.append(repo)
    if user:
        cmd.append('-u %s' % (user))
    if try_syntax == None:
        try_syntax = ''
    if try_run:
        # if there is no try_syntax, try defaults will get triggered by the 'try: ' alone
        if config.get('staging', False):
            cmd.extend(['-m "try: %s -n bug %s"' % (try_syntax, bug_id)])
        else:
            cmd.extend(['-m "try: %s -n --post-to-bugzilla bug %s"' % (try_syntax, bug_id)])
    cmd.append(patch)
    print cmd
    (out, err, rc) = run_hg(cmd)
    return (rc, err)

def process_patchset(data):
    """
    Process, apply, and push the patchset to the correct location.
    If try_run is specified, it will be pushed to try, and otherwise
    will be pushed to branch if the credentials are correct.

    process_patchset returns a 2-tuple, (return_code, comment).
    Comment will be none in the case of an error, as the message is sent
    out by process_patchset.
    There should always be a comment posted.
    """
    active_repo = os.path.join('active/%s' % (data['branch']))
    try_run = (data['try_run'] == True)
    if 'push_url' in data:
        push_url = data['push_url']
    else:
        push_url = data['branch_url']
    push_url = push_url.replace('https', 'ssh', 1)

    # The comment header. The comment is constructed incrementally at any possible
    # failure/success point.
    comment_hdr = ['Autoland Patchset:\n\tPatches: %s\n\tBranch: %s%s'
            % (', '.join(map(lambda x: str(x['id']), data['patches'])), data['branch'],
               (' => try' if try_run else ''))]
    comment = comment_hdr

    class RETRY(Exception):
        pass

    def cleanup_wrapper():
        # use an attribute full_clean in order to keep track of
        # whether or not a full cleanup is required.
        # This is done since cleanup_wrapper's scope doesn't let us
        # access process_patchset globals, given the way it is used.
        if not hasattr(cleanup_wrapper, 'full_clean'):
            cleanup_wrapper.full_clean = False
        if not hasattr(cleanup_wrapper, 'branch'):
            cleanup_wrapper.branch = data['branch']
        if cleanup_wrapper.branch != data['branch']:
            cleanup_wrapper.full_clean = False
            cleanup_wrapper.branch = data['branch']
        # only wipe the repositories every second cleanup
        if cleanup_wrapper.full_clean:
            clear_branch(data['branch'])
            log_msg('Wiped repositories for: %s' % data['branch'])
        else:
            active_repo = os.path.join('active', data['branch'])
            update(active_repo)
            log_msg('Update -C on active repo for: %s' % data['branch'])
        cleanup_wrapper.full_clean = not cleanup_wrapper.full_clean

        clone_revision = clone_branch(data['branch'], data['branch_url'])
        if clone_revision == None:
            # TODO: Handle clone error -- Code Review question
            log_msg('[HgPusher] Clone error...')
        return

    def apply_patchset(dir, attempt):
        if not clone_branch(data['branch'], data['branch_url']):
            msg = 'Branch %s could not be cloned.'
            log_msg('[Branch %s] Could not clone from %s.' \
                    % (data['branch'], data['branch_url']))
            comment.append(msg)
            raise RETRY

        for patch in data['patches']:
            log_msg("Getting patch %s" % (patch['id']), None)
            # store patches in 'patches/' below work_dir
            patch_file = bz.get_patch(patch['id'],
                    os.path.join('patches'),create_path=True)
            if not patch_file:
                msg = 'Patch %s could not be fetched.' % (patch['id'])
                log_msg(msg)
                if msg not in comment:
                    comment.append(msg)
                raise RETRY
            valid_header = has_valid_header(patch_file)
            if not try_run and not valid_header:
                log_msg('[Patch %s] Invalid header.' % (patch['id']))
                # append comment to comment
                msg = 'Patch %s does not have a properly formatted header.' \
                        % (patch['id'])
                if msg not in comment:
                    comment.append(msg)
                raise RETRY

            user = None
            if not valid_header:
                # This is a try run, since we haven't exited
                # so author header not needed. Place in the author information
                # from bugzilla as committer.
                user='%s <%s>' % (patch['author']['name'], patch['author']['email'])

            (patch_success,err) = import_patch(active_repo, patch_file,
                    try_run, bug_id=data.get('bug_id', None),
                    user=user, try_syntax=data.get('try_syntax', None))
            if patch_success != 0:
                log_msg('[Patch %s] %s' % (patch['id'], err))
                msg = 'Error applying patch %s to %s.\n%s' \
                        % (patch['id'], data['branch'], err)
                if msg not in comment:
                    comment.append(msg)
                raise RETRY
        return True

    if not has_sufficient_permissions(data['patches'],
            data['branch'] if not try_run else 'try'):
        msg = 'Insufficient permissions to push to %s' \
                % ((data['branch'] if not try_run else 'try'))
        log_msg(msg)
        comment.append(msg)
        log_msg('Comment "%s" to bug %s' % ('\n'.join(comment), data['bug_id']), log.DEBUG)
        return (False, '\n'.join(comment))

    try:
        retry(apply_and_push, cleanup=cleanup_wrapper,
                retry_exceptions=(RETRY,),
                args=(active_repo, push_url, apply_patchset, 1),
                kwargs=dict(ssh_username=config['hg_username'],
                            ssh_key=config['hg_ssh_key'],
                            force=try_run))     # Force only on try pushes
        revision = get_revision(active_repo)
        shutil.rmtree(active_repo)
    except (HgUtilError, RETRY) as error:
        msg = 'Could not apply and push patchset:\n%s' % (error)
        log_msg('[PatchSet] %s' % (msg))
        comment.append(msg)
        log_msg('Comment "%s" to bug %s' % ('\n'.join(comment), data['bug_id']), log.DEBUG)
        # TODO need to remove whiteboard tag here or in autoland_queue?
        return (False, '\n'.join(comment))

    # Successful push. Clear any errors that might be in the comments
    comment = comment_hdr

    if try_run:
        # comment to bug with link to the try run on tbpl and in hg
        comment.append('\tDestination: http://hg.mozilla.org/try/rev/%s' % (revision))
        comment.append('Try run started, revision %s. To cancel or monitor the job, see: %s'
                % (revision, os.path.join(config['tbpl_url'],
                                          '?tree=Try&rev=%s' % (data['branch'], revision))) )
    else:
        comment.append('\tDestination: http://hg.mozilla.org/%s/rev/%s' % (data['branch'],revision))
        comment.append('Successfully applied and pushed patchset.\n\tRevision: %s'
                % (revision, data['branch'],
                   ', '.join(map(lambda x: x['id'], data['patches']))))
        if data['branch'] == 'mozilla-central':
            comment.append('To monitor the commit, see: %s'
                    % (os.path.join(config['tbpl_url'],
                       '?tree=Firefox&rev=%s' % (revision))))
        elif data['branch'] == 'mozilla-inbound':
            comment.append('To monitor the commit, see: %s'
                    % (os.path.join(config['tbpl_url'],
                       '?tree=Mozilla-Inbound&rev=%s' % (revision))))

    log_msg('Comment %s to bug %s' % ('\n'.join(comment), data['bug_id']), log.DEBUG)
    return (revision, '\n'.join(comment))

def clone_branch(branch, branch_url):
    """
    Clone tip of the specified branch.
    """
    remote = branch_url
    # Set up the clean repository if it doesn't exist,
    # otherwise, it will be updated.
    clean = os.path.join('clean')
    clean_repo = os.path.join(clean, branch)
    if not os.access(clean, os.F_OK):
        log_msg(os.getcwd())
        os.mkdir(clean)
    try:
        mercurial(remote, clean_repo)
    except subprocess.CalledProcessError as e:
        log_msg('[Clone] error cloning \'%s\' into clean repository:\n%s'
                % (remote, e))
        return None
    # Clone that clean repository to active and return that revision
    active = os.path.join('active')
    active_repo = os.path.join(active, branch)
    if not os.access(active, os.F_OK):
        os.mkdir(active)
    elif os.access(active_repo, os.F_OK):
        shutil.rmtree(active_repo)
    try:
        print 'Cloning from %s -----> %s' % (clean_repo, active_repo)
        revision = mercurial(clean_repo, active_repo)
        log_msg('[Clone] Cloned revision %s' %(revision), log.info)
    except subprocess.CalledProcessError as error:
        log_msg('[Clone] error cloning \'%s\' into active repository:\n%s'
                % (remote, error))
        return None

    return revision

def clear_branch(branch):
    """
    Clear the directories for the given branch,
    effictively removing any changes as well as clearing out the clean repo.
    """
    clean_repo = os.path.join('clean/', branch)
    active_repo = os.path.join('active/', branch)
    if os.access(clean_repo, os.F_OK):
        shutil.rmtree(clean_repo)
    if os.access(active_repo, os.F_OK):
        shutil.rmtree(active_repo)

def valid_dictionary_structure(d, elements):
    """
    Check that the given dictionary contains all elements.
    """
    for element in elements:
        if element not in d:
            return False
    return True

def valid_job_message(message):
    """
    Verify that the 'job' message has valid data & structure.
    This also ensures that the patchset has the correct data.
    """
    if not valid_dictionary_structure(message,
            ['bug_id','branch','branch_url','try_run','patches']):
        log_msg('Invalid message: %s' % (message))
        return False
    for patch in message['patches']:
        if not valid_dictionary_structure(patch,
                ['id', 'author', 'reviews']) or \
           not valid_dictionary_structure(patch['author'],
                ['email', 'name']):
            log_msg('Invalid patchset in message.')
            return False
        if not message['try_run']:
            for review in patch['reviews']:
                if not valid_dictionary_structure(review,
                    ['reviewer', 'type', 'result']):
                    log_msg('Invalid review in patchset')
                    return False
                if not valid_dictionary_structure(review['reviewer'],
                    ['email', 'name']):
                    log_msg('Invalid reviewer')
                    return False
    return True

def message_handler(message):
    """
    Handles all incoming messages.
    """
    data = message['payload']

    if 'job_type' not in data:
        log_msg('[HgPusher] Erroneous message: %s' % (message))
        return
    if data['job_type'] == 'command':
        pass
    elif data['job_type'] == 'patchset':
        # check that all necessary data is present
        if not valid_job_message(data):
            # comment?
            # XXX: This is a bit more important than this...
            print "Not valid job message %s" % data
            return

        if data['branch'] == 'try':
            # Change branch, branch_url to pull from mozilla-central on a try run
            data['push_url'] = data['branch_url']
            data['branch'] = 'mozilla-central'
            data['branch_url'] = data['branch_url'].replace('try','mozilla-central', 1)

        clone_revision = None
        for attempts in range(3):
            clone_revision = clone_branch(data['branch'], data['branch_url'])
            if clone_revision:
                break
        if clone_revision == None:
            log_msg('[HgPusher] Clone error...')
            msg = { 'type' : 'error', 'action' : 'repo.clone',
                    'patchsetid' : data['patchsetid'],
                    'bug_id' : data['bug_id'],
                    'comment' : 'Autoland Error:\n\tCould note clone repository %s' % (data['branch']) }
            mq.send_message(msg, 'db')
            return
        (patch_revision, comment) = process_patchset(data)
        if patch_revision and patch_revision != clone_revision:
            # comment already posted in process_patchset
            log_msg('[Patchset] Successfully applied patchset %s'
                % (patch_revision), log.info)
            msg = { 'type'  : 'success',
                    'action': 'try.push' if data['try_run'] else 'branch.push',
                    'bug_id' : data['bug_id'], 'patchsetid': data['patchsetid'],
                    'revision' : patch_revision,
                    'comment' : comment }
            mq.send_message(msg, 'db')
        else:
            # error came when applying a ptch.
            msg = { 'type' : 'error', 'action' : 'patchset.apply',
                    'patchsetid' : data['patchsetid'],
                    'bug_id' : data['bug_id'],
                    'comment' : comment }
            mq.send_message(msg, 'db')

def main():
    # set up logging
    log.basicConfig(format=LOGFORMAT, level=log.DEBUG,
            filename=LOGFILE, handler=LOGHANDLER)

    mq.set_host(config['mq_host'])
    mq.set_exchange(config['mq_exchange'])
    mq.connect()

    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            if arg == '--purge-queue':
                # purge the autoland queue
                mq.purge_queue(config['mq_hgp_queue'], prompt=True)
                exit(0)

    try:
        if not os.access(config['work_dir'], os.F_OK):
            os.makedirs(config['work_dir'])
        os.chdir(config['work_dir'])

        # look for available (not locked) hgpusher.# in the working directoy
        i = 0
        while True:
            hgp_lock = None
            work_dir = 'hgpusher.%d' % (i)
            if not os.access(work_dir, os.F_OK):
                os.makedirs(work_dir)
            try:
                print "Trying dir: %s" % (work_dir)
                hgp_lock = lock.lock(os.path.join(work_dir, '.lock'), timeout=1)
                print "Working directory: %s" % (work_dir)
                os.chdir(work_dir)
                # get rid of active dir
                if os.access('active/', os.F_OK):
                    shutil.rmtree('active/')
                os.makedirs('active/')

                mq.listen(queue=config['mq_hgp_queue'], callback=message_handler,
                        routing_key='hgpusher')
            except error.LockHeld:
                # couldn't take the lock, check next workdir
                i += 1
                continue
            else:
                hgp_lock.release()
                print "Released working directory"
                break
    except os.error, e:
        log_msg('Error switching to working directory: %s' % e)
        exit(1)

if __name__ == '__main__':
    os.chdir(base_dir)
    main()

