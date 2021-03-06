import site
site.addsitedir('vendor')
site.addsitedir('vendor/lib/python')

import os, sys
import re
import subprocess
import logging
import logging.handlers
import shutil
from mercurial import error, lock   # For lockfile on working dirs

from utils import bz_utils, mq_utils, common, ldap_utils
BASE_DIR = common.get_base_dir(__file__)
site.addsitedir('%s/../../lib/python' % (BASE_DIR))

from util.hg import mercurial, apply_and_push, HgUtilError, \
                    update, get_revision
from util.retry import retry, retriable
from util.commands import run_cmd

log = logging.getLogger()
LOGFORMAT = logging.Formatter(
        '%(asctime)s\t%(module)s\t%(funcName)s\t%(message)s')
LOGFILE = os.path.join(BASE_DIR, 'hgpusher.log')
LOGHANDLER = logging.handlers.RotatingFileHandler(LOGFILE,
                    maxBytes=50000, backupCount=5)
mq = mq_utils.mq_util()

config = common.get_configuration([os.path.join(BASE_DIR, 'config.ini'),
                                   os.path.join(BASE_DIR, 'secrets.ini')])
bz = bz_utils.bz_util(api_url=config['bz_api_url'], url=config['bz_url'],
        attachment_url=config['bz_attachment_url'],
        username=config['bz_username'], password=config['bz_password'])
ldap = ldap_utils.ldap_util(config['ldap_host'], int(config['ldap_port']),
        config['ldap_bind_dn'], config['ldap_password'])
mq = mq_utils.mq_util(host=config['mq_host'],
                      vhost=config['mq_vhost'],
                      username=config['mq_username'],
                      password=config['mq_password'],
                      exchange=config['mq_exchange'])

class RetryException(Exception):
    """
    Used to trigger a retry when using retriable functions.
    """
    pass
class FailException(Exception):
    """
    Used to fail immediately without retry when using retriable functions.
    """
    pass

class RepoCleanup(object):
    """
    Used for cleaning up the active/clean repositories for
    the specified branch.
    """
    def __init__(self, branch, url):
        self.i = 0
        self.branch = branch
        self.url = url

    def __call__(self):
        self.i += 1
        if self.i == 2:
            self.hard_clean()
        else:
            self.soft_clean()

    def soft_clean(self):
        """
        Only does an update -C on the active repository
        to get rid of any applied, not committed patches.
        """
        active_repo = os.path.join('active', self.branch)

        # get rid of any imported and qpush-ed patches
        log.debug('qpop -a and rm -rf .hg/patches')
        (success, err, ret) = run_hg(['qpop', '-a'])
        run_cmd(['rm', '-rf', os.path.join(active_repo, '.hg/patches')])

        log.debug('Update -C on active repo for: %s' % (self.branch))
        update(active_repo)

    def hard_clean(self):
        """
        Deletes the clean and active repositories & re-clones.
        """
        clear_branch(self.branch)
        log.debug('Wiped repositories for: %s' % (self.branch))
        try:
            cloned_revision = clone_branch(self.branch, self.url)
        except RetryException:
            log.error('[HgPusher] Clone error while cleaning')
            # XXX: do something....


class Patch(object):
    def __init__(self, patch):
        self.num = patch['id']
        self.author_name = patch['author']['name']
        self.author_email = patch['author']['email']
        self.reviews = patch.get('reviews', None)
        self.file = None
        self.user = None

    def get_file(self):
        """
        Download patch file to the 'patches' dir. Return the file name,
        or None on failure.
        """
        log.debug("Getting patch %s" % (self.num))
        self.file = bz.get_patch(self.num, 'patches', create_path=True)
        return self.file

    def fill_user(self):
        """
        Fill the user string from author info.
        """
        self.user = '%s <%s>' % (self.author_name, self.author_email)

    def delete(self):
        """
        Delete the file from the filesystem.
        """
        try:
            if self.file:
                os.remove(self.file)
        except OSError, err:
            log.error('File %s could not be deleted.' % (self.file))
        self.file = None


class Patchset(object):
    def __init__(self, ps_id, bug_id, patches, try_run, push_url,
            branch, branch_url, try_syntax=None):
        """
        Creates a Patchset object.
        Fills in an active_repo field to point to a directory for
            the specified branch.
        If try_syntax not specified, uses the default.
        """
        self.num = ps_id
        self.bug_id = bug_id
        self.patches = [Patch(patch) for patch in patches]
        self.try_run = try_run
        self.push_url = push_url
        self.branch = branch
        self.branch_url = branch_url
        if try_syntax != None:
            self.try_syntax = try_syntax
        else:
            self.try_syntax = config['hg_try_syntax']

        self.active_repo = os.path.join('active/%s' % (branch))
        self.comment = ''
        self.setup_comment()

    def setup_comment(self):
        """
        Set up the comment with the default comment header.
        """
        self.comment = ['Autoland Patchset:\n\tPatches: %s\n\tBranch: %s%s'
                % (', '.join(str(x.num) for x in self.patches),
                   self.branch, (' => try' if self.try_run else ''))]

    def add_comment(self, msg):
        """
        Check if the comment already contains the given message. If not,
        append it to the comment.
        """
        if not msg in self.comment:
            self.comment.append(msg)

    def process(self):
        """
        Process this patchset, doing the following:
            1. Check permissions on each patch
            2. Clone the repository
            3. Apply patches, with 3 attempts
        """
        # 1. Check permissions on each patch
        if not has_sufficient_permissions(self.patches,
                self.branch if not self.try_run else 'try'):
            log.error('Insufficient permissions to push to %s.'
                    % (self.branch if not self.try_run else 'try'))
            self.add_comment('Insufficient permissions to push to %s.'
                    % (self.branch if not self.try_run else 'try'))
            return (False, '\n'.join(self.comment))
        # 2. Clone the repository
        cloned_rev = None
        try:
            cloned_rev = clone_branch(self.branch, self.branch_url)
        except RetryException:
            log.error('[Branch %s] Could not clone from %s.'
                    % (self.branch, self.branch_url))
            self.add_comment('An error occurred while cloning %s.'
                    % (self.branch_url))
            return (False, '\n'.join(self.comment))
        # 3. Apply patches, with 3 attempts
        try:
            # make 3 attempts so that
            # 1st is on current clone,
            # 2nd attempt is after an update -C,
            # 3rd attempt is a fresh clone
            retry(apply_and_push, attempts=3,
                    retry_exceptions=(RetryException),
                    cleanup=RepoCleanup(self.branch, self.branch_url),
                    args=(self.active_repo, self.push_url,
                          self.apply_patches, 1),
                    kwargs=dict(ssh_username=config['hg_username'],
                                ssh_key=config['hg_ssh_key'],
                                force=self.try_run))    # force only on try
            revision = get_revision(self.active_repo)
            shutil.rmtree(self.active_repo)
            for patch in self.patches:
                patch.delete()
        except (HgUtilError, RetryException, FailException), err:
            # Failed
            log.error('[PatchSet] Could not be applied and pushed.\n%s'
                    % (err))
            self.add_comment('Patchset could not be applied and pushed.'
                             '\n%s' % (err))
            return (False, '\n'.join(self.comment))
        except (OSError), err:
            # There was an error with the active_repo location
            log.error('An error occurred: %s' % (err))
            self.add_comment('Patchset could not be applied and pushed.'
                             '\nAn unexpected error occurred')
            return (False, '\n'.join(self.comment))
        # Success
        self.setup_comment() # Clear the comment
        if self.try_run:
            # comment to bug with link to the try run on tbpl and in hg
            self.add_comment('\tDestination: '
                    'http://hg.mozilla.org/try/pushloghtml?changeset=%s'
                        % (revision))
            self.add_comment('Try run started, revision %s.'
                    ' To cancel or monitor the job, see: %s'
                    % (revision, os.path.join(config['tbpl_url'],
                                            '?tree=Try&rev=%s' % (revision))))
        else:
            # comment to bug with push information
            self.add_comment('\tDestination: '
                    'http://hg.mozilla.org/%s/pushloghtml?changeset=%s'
                            % (self.branch, revision))
            self.add_comment('Successfully applied and pushed patchset.\n'
                    '\tRevision: %s' % (revision))
            if self.branch == 'mozilla-central':
                self.add_comment('To monitor the commit, see: %s'
                        % (os.path.join(config['tbpl_url'],
                           '?tree=Firefox&rev=%s' % (revision))))
            elif self.branch == 'mozilla-inbound':
                self.add_comment('To monitor the commit, see: %s'
                        % (os.path.join(config['tbpl_url'],
                           '?tree=Mozilla-Inbound&rev=%s' % (revision))))
        return (revision, '\n'.join(self.comment))

    def apply_patches(self, branch_dir, attempt):
        """
        apply_patches() is meant to be passed to apply_and_push.
        First verify the patchset, and then import & commit each patch.
        If anything fails, RetryException will be raised.
        """
        self.verify()
        self.finish_import()

    def verify(self):
        """
        Verify the following for each patch:
            1. The patch exists and can be downloaded
            2. has valid headers. If try run, put user data into patch.user
            3. patch applies using 'import --no-commit -f'
        """
        log.debug('Verifying patchset')
        if not self.patches:
            raise RetryException
        for patch in self.patches:
            # 1. The patch exists and can be downloaded
            if not patch.get_file():
                log.error('[Patch %s] Couldn\'t be fetched.' % (patch.num))
                self.add_comment('Patch %s couldn\'t be fetched.'
                        % (patch.num))
                raise RetryException

            # 2. has valid headers. If try run, put user data into patch.user
            valid_header = has_valid_header(patch.file)
            if not valid_header:
                # check branch name, since self.try_run is set to true even if
                # it is a try run for a branch landing.
                # On a branch landing, valid headers are required. This means
                # that the job should fail on the try run.
                if not self.branch.lower() == 'try':
                    log.error('[Patch %s] Invalid header.' % (patch.num))
                    self.add_comment('Patch %s doesn\'t have '
                            'a properly formatted header. To land to branches,'
                            ' patches must contain a header with a commit '
                            'message and user field.'
                            % (patch.num))
                    raise FailException
                # on a try run, fill in the user information
                patch.fill_user()
            # 3. patch applies using 'qimport; qpush'
            (patch_success, err) = import_patch(self.active_repo,
                    patch.file, self.try_run, user=patch.user,
                    try_syntax=self.try_syntax, bug_id=self.bug_id)
            if not patch_success:
                log.error('[Patch %s] could not verify import:\n%s'
                        % (patch.num, err))
                self.add_comment('Patch %s could not be applied to %s.\n%s'
                        % (patch.num, self.branch, err))
                raise RetryException
        log.debug('Patchset is valid')

    def finish_import(self):
        """
        Perform an 'hg import' on each patch in the set.
        If this is a try run, use the patch.user field to commit.
        """
        log.debug('QFinish-ing the import.')
        cmd = ['qfinish', '-a', '-R', self.active_repo]
        (output, err, ret) = run_hg(cmd)
        if ret != 0:
            log.error('Unable to qfinish the patch queue: %s\nRetrying.'
                    % (err))
            raise RetryException


def run_hg(hg_args):
    """
    Run hg with given args, returning a tuple containing stdout,
    stderr and return code.
    """
    cmd = ['hg']
    cmd.extend(hg_args)
    log.info('Running cmd: %s' % (cmd))
    proc = subprocess.Popen(cmd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (output, err) = proc.communicate()
    ret = proc.returncode
    return (output, err, ret)

def has_valid_header(filename):
    """
    Check to see if the file has a valid header. The header must
    include author name and commit message.

    Note: this forces developers to use 'hg export' rather than 'hg diff'
          if they want to be pushing to branch.
    """
    with open(filename, 'r') as f_in:
        puser = re.compile(r'# User ')

        # Match the user line, starts with "User" and then a name
        # ends with an email address in <>
        userline = re.compile(r'# User [\w\s]+ '
                '<[\w\d._%+-]+@[\w\d.-]+\.\w{2,6}>$')

        # Commit message is always fist line not prefixed with #
        commitline = re.compile(r'^[^#$]+')

        has_userline = False
        for line in f_in:
            if puser.match(line):
                has_userline = True
                # User line must be of the form
                # # User Name <name@email.com>
                if not userline.match(line):
                    log.info('Bad header.')
                    return False
            elif commitline.match(line):
                # userline always before commit message, so if we have it along
                # with a commit message, return True, else False
                return has_userline
            elif line == '':
                # done with header since header ends with an empty line
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
        if in_ldap_group(patch.author_email, group):
            continue    # next patch
        for review in patch.reviews:
            if not review.get('reviewer'):
                continue
            if in_ldap_group(review['reviewer'], group):
                found = True
                break   # next patch
        if not found:
            return False

    return True

def import_patch(repo, patch, try_run, bug_id, user=None,
        try_syntax=config['hg_try_syntax']):
    """
    Import patch file patch into a mercurial queue.

    Import is used to pull required header information, and to
    automatically perform a commit for each patch
    """
    cmd = ['qimport', '-R', repo, patch]
    (output, err, ret) = run_hg(cmd)
    if ret != 0:
        return (ret == 0, err)
    cmd = ['qpush', '-R', repo]
    (output, err, ret) = run_hg(cmd)
    if ret != 0:
        return (ret == 0, err)

    cmd = ['qrefresh', '-R', repo]
    # if a user field specified, qrefesh that name in there
    if user:
        cmd.extend(['-u', user])

    if try_syntax == None:
        try_syntax = ''
    if try_run:
        # if there is no try_syntax,
        # try defaults will be triggered by 'try:'
        if config.get('staging', False):
            cmd.extend(['-m', 'try: %s -n bug %s' % (try_syntax, bug_id)])
        else:
            cmd.extend(['-m', 'try: %s -n --post-to-bugzilla bug %s' \
                    % (try_syntax, bug_id)])
    (output, err, ret) = run_hg(cmd)
    return (ret == 0, err)

@retriable(retry_exceptions=(RetryException,), attempts=3, sleeptime=5)
def clone_branch(branch, branch_url):
    """
    Clone tip of the specified branch.
    """
    remote = branch_url
    # Set up the clean repository if it doesn't exist,
    # otherwise, it will be updated.
    clean = os.path.join('clean')
    clean_repo = os.path.join(clean, branch)
    if not os.path.isdir(clean):
        os.mkdir(clean)
    try:
        mercurial(remote, clean_repo)
    except subprocess.CalledProcessError, err:
        log.error('[Clone] error cloning \'%s\' into clean repository:\n%s'
                % (remote, err))
        raise RetryException
        return None
    # Clone that clean repository to active and return that revision
    active = os.path.join('active')
    active_repo = os.path.join(active, branch)
    if not os.path.isdir(active):
        os.mkdir(active)
    elif os.path.isdir(active_repo):
        shutil.rmtree(active_repo)
    try:
        log.info('Cloning from %s -----> %s' % (clean_repo, active_repo))
        revision = mercurial(clean_repo, active_repo)
        log.info('[Clone] Cloned revision %s' %(revision))
    except subprocess.CalledProcessError, err:
        log.error('[Clone] error cloning \'%s\' into active repository:\n%s'
                % (remote, err))
        raise RetryException
        return None

    return revision

def clear_branch(branch):
    """
    Clear the directories for the given branch,
    effictively removing any changes as well as clearing out the clean repo.
    """
    clean_repo = os.path.join('clean', branch)
    active_repo = os.path.join('active', branch)
    try:
        shutil.rmtree(clean_repo)
        shutil.rmtree(active_repo)
    except:
        pass

def valid_dictionary_structure(dict_, elements):
    """
    Check that the given dictionary contains all elements.
    """
    for element in elements:
        if element not in dict_:
            return False
    return True

def valid_job_message(message):
    """
    Verify that the 'job' message has valid data & structure.
    This also ensures that the patchset has the correct data.
    """
    if not valid_dictionary_structure(message,
            ['bug_id','branch','branch_url','try_run','patches']):
        log.error('Invalid message: %s' % (message))
        return False
    for patch in message['patches']:
        if not valid_dictionary_structure(patch,
                ['id', 'author', 'reviews']) or \
           not valid_dictionary_structure(patch['author'],
                ['email', 'name']):
            log.error('Invalid patchset in message.')
            return False
        if not message['try_run']:
            for review in patch['reviews']:
                if not valid_dictionary_structure(review,
                    ['reviewer', 'type', 'result']):
                    log.error('Invalid review in patchset')
                    return False
                if not valid_dictionary_structure(review['reviewer'],
                    ['email', 'name']):
                    log.error('Invalid reviewer')
                    return False
    return True

@mq.generate_callback
def message_handler(message):
    """
    Handles all incoming messages.
    """
    data = message['payload']

    if 'job_type' not in data:
        log.error('[HgPusher] Erroneous message: %s' % (message))
        return
    if data['job_type'] == 'command':
        pass
    elif data['job_type'] == 'patchset':
        # check that all necessary data is present
        if not valid_job_message(data):
            # comment?
            # XXX: This is a bit more important than this...
            log.error('Not valid job message %s' % (data))
            return

        if data['branch'] == 'try':
            # This is a job that was flagged specifically for try,
            # not a branch landing on its try iteration.
            # default to pulling from mozilla-central on a try run
            data['branch'] = 'mozilla-central'
            data['branch_url'] = data['branch_url'].replace('try',
                                                        'mozilla-central', 1)
        if 'push_url' not in data:
            data['push_url'] = data['branch_url']
        data['push_url'] = data['push_url'].replace('https', 'ssh', 1)
        data['push_url'] = data['push_url'].replace('http', 'ssh', 1)

        patchset = Patchset(data['patchsetid'],
                        data['bug_id'],
                        data['patches'],
                        bool(data['try_run']),
                        data['push_url'],
                        data['branch'], data['branch_url'],
                        data.get('try_syntax', None))

        (patch_revision, comment) = patchset.process()
        if patch_revision:
            log.info('[Patchset] Successfully applied patchset %s'
                % (patch_revision))
            msg = { 'type'  : 'SUCCESS',
                    'action': 'TRY.PUSH' if patchset.try_run \
                                         else 'BRANCH.PUSH',
                    'bug_id' : patchset.bug_id,
                    'patchsetid': patchset.num,
                    'revision' : patch_revision,
                    'comment' : comment }
            mq.send_message(msg, 'db')
        else:
            # error came when processing the patchset
            msg = { 'type' : 'ERROR', 'action' : 'PATCHSET.APPLY',
                    'patchsetid' : patchset.num,
                    'bug_id' : patchset.bug_id,
                    'comment' : comment }
            mq.send_message(msg, 'db')

def main():
    # set up logging
    log.setLevel(logging.DEBUG)
    LOGHANDLER.setFormatter(LOGFORMAT)
    log.addHandler(LOGHANDLER)

    mq.set_host(config['mq_host'])
    mq.set_exchange(config['mq_exchange'])
    mq.connect()
    mq.declare_and_bind(config['mq_hgp_queue'], 'hgpusher')

    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            if arg == '--purge-queue':
                # purge the autoland queue
                mq.purge_queue(config['mq_hgp_queue'], prompt=True)
                exit(0)

    try:
        if not os.path.isdir(config['work_dir']):
            os.makedirs(config['work_dir'])
        os.chdir(config['work_dir'])

        # look for available (not locked) hgpusher.# in the working directoy
        i = 0
        while True:
            hgp_lock = None
            work_dir = 'hgpusher.%d' % (i)
            if not os.path.isdir(work_dir):
                os.makedirs(work_dir)
            try:
                log.debug('Trying dir: %s' % (work_dir))
                hgp_lock = lock.lock(os.path.join(work_dir, '.lock'),
                        timeout=1)
                log.debug('Working directory: %s' % (work_dir))
                os.chdir(work_dir)
                # get rid of active dir
                try:
                    shutil.rmtree('active')
                except OSError:
                    pass
                os.makedirs('active')

                mq.listen(queue=config['mq_hgp_queue'],
                        callback=message_handler)
            except error.LockHeld:
                # couldn't take the lock, check next workdir
                i += 1
                continue
            finally:
                if hgp_lock:
                    hgp_lock.release()
                    log.debug('Released working directory')
                    raise
    except Exception, err:
        log.error('An error occurred: %s' % (err))
        exit(1)

if __name__ == '__main__':
    os.chdir(BASE_DIR)
    main()

