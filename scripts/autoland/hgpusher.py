import os, sys, signal
import re
import tempfile, ConfigParser
import subprocess
import logging as log
import logging.handlers
import shutil

sys.path.append(os.path.join(os.path.dirname(__file__), "../../lib/python"))

from util.hg import mercurial, apply_and_push, cleanOutgoingRevs, out, \
        remove_path, HgUtilError, update, get_revision
from util.retry import retry
import utils.mjessome_bz_utils as bz_utils
import utils.mq_utils as mq_utils
import utils.common as common

base_dir = os.path.abspath(os.path.dirname(os.path.realpath(__file__))+'/../')

LOGFORMAT = '%(asctime)s\t%(module)s\t%(funcName)s\t%(message)s'
LOGFILE = os.path.join(base_dir, 'hgpusher.log')
LOGHANDLER = log.handlers.RotatingFileHandler(LOGFILE,
                    maxBytes=50000, backupCount=5)
mq = mq_utils.mq_util()
base_dir = os.path.dirname(os.path.realpath(__file__)) + '/../'
base_dir = os.path.abspath(base_dir)
config = common.get_configuration(os.path.join(base_dir, 'config.ini'))
config.update(common.get_configuration(os.path.join(base_dir, 'auth.ini')))
bz = bz_utils.bz_util(config['bz_api_url'], config['bz_attachment_url'],
        config['bz_username'], config['bz_password'])

def run_hg(hg_args):
    """
    Run hg with given args, returning a tuple containing
    stdout string, stderr string, and return code.
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

def has_valid_header(file, try_push=False):
    """
    Checks to see if file has a valid header. The header must include author,
    name, and commit message. The commit message must start with 'bug \d+:'
    """
    f = open(file, 'r')
    for line in f:
        if re.match('# User ', line):
            if not re.match('# User [\w\s]+ <[\w\d._%+-]+@[\w\d.-]+\.\w{2,6}>$', line):
                return False
        elif re.match('^bug (\d+|\w+)[:\s]', line, re.I):
            # comment line
            return True
        elif re.match('^$', line):
            # done with header
            break
    return False

def process_patchset(data):
    """
    Apply patches and push to branch repository.
    """
    remote = '%s%s' % (config['hg_base_url'], data['branch'])
    active_repo = 'active/%s' % (data['branch'])
    fail_messages = []
    def cleanup_wrapper():
        try:
            shutil.rmtree(active_repo)
            clone_branch(data['branch'])
        except subprocess.CalledProcessError:
            # something useful needs to be done here
            log_msg('Error while cleaning/replacing repository.')

    def apply_patchset(dir, attempt):
        for patch in data['patches']:
            log_msg("Getting patch %s" % (patch['id']), None)
            # store patches in 'patches/' below work_dir
            patch_file = bz.get_patch(patch['id'], 'patches', create_path=True)
            if not has_valid_header(patch_file, data['branch'] == 'try'):
                log_msg('[Patch %s] invalid header.' % (patch['id']))
                msg = {
                    'type'    : 'error',
                    'action'  : 'patch.header',
                    'bugid'   : data['bugid'],
                    'branch'  : data['branch'],
                    'patchid' : patch['id'],
                    'patchsetid' : data['patchsetid'],
                    }
                if msg not in fail_messages:
                    fail_messages.append(msg)
                return False

            # using import to patch, this will pull required header information
            # and automatically perform commit for each import.
            (out, err, rc) = run_hg(['import', '-R', active_repo, patch_file])
            if rc != 0:
                log_msg('[Patch %s] %s' % (patch['id'], err))
                msg = {
                    'type'       : 'error',
                    'action'     : 'patch.import',
                    'bugid'      : data['bugid'],
                    'branch'     : data['branch'],
                    'patchid'    : patch['id'],
                    'patchsetid' : data['patchsetid']
                    }
                if msg not in fail_messages:
                    fail_messages.append(msg)
                return False
        return True

    try:
        retry(apply_and_push, cleanup=cleanup_wrapper,
                retry_exceptions=Exception('E_RETRY'),
                args=(active_repo, remote, apply_patchset, 1),
                kwargs=dict(ssh_username=config['hg_username'],ssh_key=config['hg_ssh_key']))
    except HgUtilError as error:
        log_msg('[PatchSet] Could not apply and push patchset:\n%s' % (error))
        mq.send_message(fail_messages, config['mq_queue'],
                routing_keys=[config['mq_comment_topic'],
                              config['mq_db_topic']])
        return False
    except Exception('E_RETRY'):
        log_msg('[PatchSet] Could not apply and push patchset.')
        mq.send_message(fail_messages, config['mq_queue'],
                routing_keys=[config['mq_comment_topic'],
                              config['mq_db_topic']])
        return False
    revision = get_revision(active_repo)
    shutil.rmtree(active_repo)
    return revision

def clone_branch(branch):
    """
    Clone the tip of the specified branch.
    """
    remote = '%s%s' % (config['hg_base_url'], branch)
    # Set up the local/clean repository if it doesn't exist,
    # otherwise, it will update.
    clean = 'clean/%s' % (branch)
    if not os.access('clean', os.F_OK):
        os.mkdir('clean')
    try:
        mercurial(remote, clean)
    except subprocess.CalledProcessError as error:
        log_msg('[Clone] error cloning \'%s\' into local repository :\n%s'
                %(remote,error))
        return None
    # Clone that local repository and return that revision
    active = 'active/%s' % (branch)
    if not os.access('active', os.F_OK):
        os.mkdir('active')
    elif os.access(active, os.F_OK):
        shutil.rmtree(active)
    try:
        revision = mercurial(clean, active)
        log_msg('[Clone] Cloned revision %s' % (revision))
    except subprocess.CalledProcessError as error:
        log_msg('[Clone] error cloning \'%s\' into active repository :\n%s'
                %(remote,error))
        return None

    return revision

def valid_patchset_data(data):
    for element in ['bugid', 'branch', 'patchsetid', 'patches']:
        if element not in data:
            mq.send_message('ERROR %s not specified.'
                    % (element.capitalize()), config['mq_queue'],
                    config['mq_db_topic'])
            log_msg("Missing element: %s" % (element))
            return False
    if not isinstance(data['patches'], list):
        return False
    for item in data['patches']:
        for element in ['id', 'author', 'reviewer']:
            if element not in item:
                mq.send_message('ERROR %s not specified for patch.'
                        % (element.capitalize()),
                        config['mq_db_topic'])
                log_msg("Patch missing element: %s" % (element))
                return False
    return True

def message_handler(message):
    """
    Handles all messages that are coming through and performs
    the correct checks and actions on each.
    """
    os.chdir(config['work_dir'])
    data = message['payload']
    if 'job_type' not in data:
        log_msg('[HgPusher] Erroneous message: %s' % (message))
        return
    if data['job_type'] == 'command':
        if data['command'] == 'stop':
            # clean up and quit
            pass
        if data['command'] == 'backout':
            #backout a specified changeset
            pass
    elif data['job_type'] == 'patchset':
        # check that all necessary data is present
        if valid_patchset_data(job_info):
            clone_revision = clone_branch(data['branch'])
            if clone_revision == None:
                # Handle the clone error
                log_msg("[HgPusher] Clone error...")
                return
            patch_revision = process_patchset(job_info)
            if patch_revision and patch_revision != clone_revision:
                log_msg('[Patchset] Successfully applied patchset %s'
                        % (patchsetid))
                msg = {
                    'type'       : 'success',
                    'action'     : 'push',
                    'bugid'      : job_info['bugid'],
                    'branch'     : job_info['branch'],
                    'revision'   : patch_revision,
                    'patchsetid' : job_info['patchsetid'],
                    }
                mq.send_message(msg, config['mq_queue'],
                        routing_keys=[config['mq_comment_topic'],
                                      config['mq_db_topic']])
            else:
                # patchset failed
                msg = {
                    'type'       : 'error',
                    'action'     : 'push',
                    'bugid'      : job_info['bugid'],
                    'branch'     : job_info['branch'],
                    'patchsetid' : job_info['patchsetid'],
                    }
                mq.send_message(msg, config['mq_queue'],
                        routing_keys=[config['mq_comment_topic'],
                                      config['mq_db_topic']])


def main():
    # set up logging
    log.basicConfig(format=LOGFORMAT, level=log.DEBUG,
            filename=LOGFILE, handler=LOGHANDLER)
    log.info('Process running, PID: %s' % str(os.getpid()))

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
    daemonize = True
    pid_file = '%s/hgpusher.pid' % (base_dir)
    for arg in sys.argv[1:]:
        if arg == 'stop':
            try:
                pidfile = open(pid_file, 'r')
                os.kill(int(pidfile.read()), signal.SIGTERM)
                pidfile.close()
                os.remove(pid_file)
                exit(0)
            except IOError:
                print >>sys.stderr, 'Error: No pidfile present.'
                exit(1)
            except OSError:
                print >>sys.stderr, \
                        'Error: Process not running. Removing pidfile'
                os.remove(pid_file)
                exit(1)
        elif arg == '--fg':
            # don't daemonize
            daemonize = False
        else:
            print >>sys.stderr, 'Unknown argument %s.' % (arg)

    if os.access('hgpusher.pid', os.F_OK):
        # already running
        print >>sys.stderr,'Error: Found pidfile, is hgpusher already running?'
        exit(1)
    # no pidfile, create it
    pidfile = open(pid_file, 'w')
    if daemonize:
        try:
            pid = os.fork()
        except OSError, e:
            raise Exception, '%s [%d]' % (e.strerror, e.errno)
        if pid == 0:
            os.setsid()
            try:
                pid = os.fork()
            except OSError, e:
                raise Exception, '%s [%d]' % (e.strerror, e.errno)
            if pid == 0:
                os.chdir(base_dir)
                os.umask(0)
                # daemonized, redirect fd's
                os.close(0); os.close(1); os.close(2)
                os.open('/dev/null', os.O_RDWR)
                os.dup2(0,1); os.dup2(0,2)
            else:
                os._exit(0)
        else:
            os._exit(0)

    pidfile.write(str(os.getpid()))
    pidfile.close()
    try:
        main()
    except (KeyboardInterrupt, SystemExit):
        os.remove(pid_file)

