import os, sys
import re
import subprocess
import logging as log
import logging.handlers
import shutil

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
bz = bz_utils.bz_util(config['bz_api_url'], config['bz_attachment_url'],
        config['bz_username'], config['bz_password'])
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
        elif re.match('^bug (\d+|\w+)[:\s]', line, re.I):   # comment line
            return True
        elif re.match('^$', line):
            # done with header
            break
    return False

def has_sufficient_permissions(patches, branch):
    """
    Searches LDAP to see if any of the users (author, reviewers) have
    sufficient LDAP permissions.
    These permissions are done on a whole for the patchset, so
    if any patch is missing those permissions the whole patchset
    cannot be pushed.
    """
    def bz_email_is_member(email, group):
        email = ldap.get_member('bugzillaEmail=%s'
                % (email), ['mail'])
        try:
            email = email[0][1]['mail'][0]
        except IndexError,KeyError:
            email = []
        return email and ldap.is_member_of_group(email, group)

    group = ldap.get_branch_permissions(branch)
    if group == None:
        return False

    for patch in patches:
        found = False
        if bz_email_is_member(patch['author']['email'], group):
            continue    # next patch
        for review in patch['reviews']:
            if bz_email_is_member(review['reviewer']['email'], group):
                found = True
                break   # next patch
        if not found:
            return False

    return True

def import_patch(repo, patch, try_run):
    """
    Import patch file patch into repo.
    If it is a try run, replace commit message with "try:"

    Import is used to pull required header information, and to
    automatically perform a commit for each patch
    """
    cmd = ['import', '-R']
    cmd.append(repo)
    if try_run:
        cmd.extend(['-m', '"try:"'])
    cmd.append(patch)
    print cmd
    (out, err, rc) = run_hg(cmd)
    return (rc, err)

def process_patchset(data):
    """
    Process, apply, and push the patchset to the correct location.
    If try_run is specified, it will be pushed to try, and otherwise
    will be pushed to branch if the credentials are correct.
    """
    class RETRY(Exception):
        pass
    active_repo = os.path.join(config['work_dir'],
                    'active/%s' % (data['branch']))
    try_run = (data['try_run'] == True)
    if not 'branch_url' in data:
        # TODO: Log bad message
        return False
    push_url = data['branch_url']
    if try_run and not 'push_url' in data:
        # TODO: Log bad message...
        return False
    if 'push_url' in data:
        push_url = data['push_url']
    comment = ['Autoland Patchset:\n\tPatches: %s\n\tBranch: %s %s\n\tDestination: %s'
            % (', '.join(map(lambda x: x['id'], data['patches'])), data['branch'],
               ('try' if try_run else ''), push_url )]

    def cleanup_wrapper():
        shutil.rmtree(active_repo)
        clone_branch(data['branch'], data['branch_url'])
    def apply_patchset(dir, attempt):
        print "attempt #%s" % (attempt)
        for patch in data['patches']:
            log_msg("Getting patch %s" % (patch['id']), None)
            # store patches in 'patches/' below work_dir
            patch_file = bz.get_patch(patch['id'],
                    os.path.join(config['work_dir'],'patches'),create_path=True)
            if not patch_file:
                msg = 'Patch %s could not be fetched.' % (patch['id'])
                log_msg(msg)
                if msg not in comment:
                    comment.append(msg)
                raise RETRY
            if not try_run and not has_valid_header(patch_file):
                log_msg('[Patch %s] Invalid header.' % (patch['id']))
                # append comment to comment
                msg = 'Patch %s does not have a properly formatted header.' \
                        % (patch['id'])
                if msg not in comment:
                    comment.append(msg)
                raise RETRY

            (patch_success,err) = import_patch(active_repo, patch_file, try_run)
            if patch_success != 0:
                log_msg('[Patch %s] %s' % (patch['id'], err))
                # append comment to comment
                msg = 'Error applying patch %s to %s.\n%s' \
                        % (patch['id'], data['branch'], err)
                if msg not in comment:
                    comment.append(msg)
                raise RETRY
        return True

    if not has_sufficient_permissions(data['patches'], data['branch']):
        msg = 'Insufficient permissions to push to %s' \
                % ((data['branch'] if not try_run else 'try'))
        log_msg(msg)
        comment.append(msg)
        log_msg('%s to %s' % ('\n'.join(comment), data['bug_id']), log.DEBUG)
        bz.publish_comment('\n'.join(comment), data['bug_id'])
        return False

    if not clone_branch(data['branch'], data['branch_url']):
            return False

    try:
        retry(apply_and_push, cleanup=cleanup_wrapper,
                retry_exceptions=(RETRY,),
                args=(active_repo, push_url, apply_patchset, 1),
                kwargs=dict(ssh_username=config['hg_username'],
                            ssh_key=config['hg_ssh_key']))
        revision = get_revision(active_repo)
        shutil.rmtree(active_repo)
    except (HgUtilError, RETRY) as error:
        msg = 'Could not apply and push patchset:\n%s' % (error)
        log_msg('[PatchSet] %s' % (msg))
        comment.append(msg)
        log_msg('commenting "%s" to %s' % ('\n'.join(comment), data['bug_id']), log.DEBUG)
        bz.publish_comment('\n'.join(comment), data['bug_id'])
        mq_msg = { 'type' : 'error', 'action' : 'patchset.apply',
                   'patchsetid' : data['patchsetid'] }
        return False

    if try_run:
        # comment to bug with link to the try run on self-serve
        comment.append('Try run started, revision %s. To cancel or monitor the job, see: %s'
                % (revision, os.path.join(config['self_serve_url'],
                                          'try/rev/%s' % (revision))) )
    else:
        comment.append('Successfully applied and pushed patchset.\n\tRevision: %s\n\tBranch: %s\n\tPatches: %s'
                % (revision, data['branch'],
                   ', '.join(map(lambda x: x['id'], data['patches']))))
        comment.append('To monitor the commit, see: %s'
                % (os.path.join(config['self_serve_url'],
                   '%s/rev/%s' % (data['branch'], revision))))
    log_msg('%s to %s' % ('\n'.join(comment), data['bug_id']), log.DEBUG)
    bz.publish_comment('\n'.join(comment), data['bug_id'])
    return revision

def clone_branch(branch, branch_url):
    """
    Clone tip of the specified branch.
    """
    remote = branch_url
    # Set up the clean repository if it doesn't exist,
    # otherwise, it will be updated.
    clean = os.path.join(config['work_dir'], 'clean')
    clean_repo = os.path.join(clean, branch)
    if not os.access(clean, os.F_OK):
        os.mkdir(clean)
    try:
        mercurial(remote, clean_repo)
    except subprocess.CalledProcessError as error:
        log_msg('[Clone] error cloning \'%s\' into clean repository:\n%s'
                % (remote, error))
        return None
    # Clone that clean repository to active and return that revision
    active = os.path.join(config['work_dir'], 'active')
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
        log_message('Invalid message.')
        return False
    for patch in message['patches']:
        if not valid_dictionary_structure(patch,
                ['id', 'author', 'reviews']) or \
           not valid_dictionary_structure(patch['author'],
                ['email', 'name']):
            log_message('Invalid patchset in message.')
            return False
        for review in patch['reviews']:
            if not valid_dictionary_structure(review,
                ['reviewer', 'type', 'result']):
                log_message('Invalid review in patchset')
                return False
            if not valid_dictionary_structure(review['reviewer'],
                ['email', 'name']):
                log_message('Invalid reviewer')
                return False
    return True

def message_handler(message):
    """
    Handles all incoming messages.
    """
    os.chdir(config['work_dir'])
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
            return

        clone_revision = clone_branch(data['branch_url'], data['branch'])
        if clone_revision == None:
            # Handle clone error
            log_msg('[HgPusher] Clone error...')
            return
        patch_revision = process_patchset(data)
        if patch_revision and patch_revision != clone_revision:
            # comment already posted in process_patchset
            log_msg('[Patchset] Successfully applied patchset %s'
                % (patch_revision), log.info)
            msg = { 'type'  : 'success',
                    'action': 'try.push' if data['try_run'] else 'branch.push',
                    'bug_id' : data['bug_id'], 'patchsetid': data['patchsetid'],
                    'revision': patch_revision }
            mq.send_message(msg, config['mq_queue'],
                    routing_keys=[config['mq_db_queue']])

        else:
            # comment already posted in process_patchset
            pass

def main():
    # set up logging
    log.basicConfig(format=LOGFORMAT, level=log.DEBUG,
            filename=LOGFILE, handler=LOGHANDLER)

    mq.set_host(config['mq_host'])
    mq.set_exchange(config['mq_exchange'])
    try:
        if not os.access(config['work_dir'], os.F_OK):
            os.makedirs(config['work_dir'])
        os.chdir(config['work_dir'])
    except os.error, e:
        log_msg('Error switching to working directory: %s', e)
        exit(1)

    mq.listen(config['mq_queue'], message_handler,
            routing_keys=[config['mq_hgpusher_topic']])

if __name__ == '__main__':
    os.chdir(base_dir)
    main()

