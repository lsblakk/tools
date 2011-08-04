import time
import os, errno
import re
from autoland import mq_utils, bz_utils, common

base_dir = os.path.abspath(os.path.dirname(os.path.realpath(__file__))+'/../')
config = common.get_configuration(os.path.join(base_dir, 'config.ini'))
config.update(common.get_configuration(os.path.join(base_dir, 'auth.ini')))
bz = bz_utils.bz_util(config['bz_api_url'], config['bz_attachment_url'],
        config['bz_username'], config['bz_password'])

def get_first_tag(whiteboard):
    """
    Returns the first autoland tag in the whiteboard.
    """
    r = re.compile('\[Autoland-[^\[]+\]', re.I)
    s = r.search(whiteboard)
    if s != None:
        s = s.group()
    return s

def get_branch_from_tag(tag):
    """
    Returns the branch name from the given autoland tag.
    """
    r = re.compile('\[Autoland-([^:\]]+)', re.I)
    s = r.search(tag)
    if s == None:
        return ''
    return s.groups()[0]

def get_patchset_data(bugid, tag):
    """
    Get all patchset data prepared in the structure required by the database.
    """
    data = {'bugid' : bugid,
            'branch' : get_branch_from_tag(tag),
            'patches' : []}
    r = re.compile('\d+')
    bug_data = bz.request('bug/%s' % bugid)
    if 'attachments' not in bug_data:
        # Log error that the bug is not good
        return None
    for id in r.finditer(tag):
        found = False
        for attachment in bug_data['attachments']:
            print attachment['id']
            print id
            if str(attachment['id']) == str(id.group()):
                patch_info = bz.get_attachment_info(attachment)
                data['patches'].append(patch_info)
                found = True
                break
        if not found:
            # Log error that the patch DNE
            return None
    if len(data['patches']) == 0:
        data['patches'] = bz.get_bug_patchset(bugid)
    return data

def bz_search_handler(interval=120):
    """
    Search bugzilla whiteboards for Autoland jobs.
    Search on the specified interval (in seconds).
    """
    bugs = bz.get_matching_bugs('whiteboard', '\[autoland-.*\]')
    for bug in bugs:
        tag = get_first_tag(bug[1])
        print bug[0], tag
        bz.remove_whiteboard_tag('\[autoland-.*\]', bug[0])
        data = get_patchset_data(bug[0], tag)
        print data
        # add it to the queue, and get patchset id
        patchset = db.enqueue(data)

def message_handler(message):
    """
    Handles json messages received. Expected structures are as follows:
    For a JOB:
        {
            'type' : 'job',
            'bugid' : '12345',
            'branch' : 'mozilla-central',
            'patches' : [ '53432', '64512' ],
        }
    For a PRIORITY CHANGE:
        {
            'type' : 'priority',
            'patchsetid' : '5453',
            'priority' : '50',
        }
    For a SUCCESS/FAILURE:
        {
            'type' : 'error',
            'action' : 'patch.import',
            'bugid' : '85834',
            'patchid' : '842582',
            'patchsetid' : '123',
        }
    """
    data =  message['payload']
    if data['type'] == 'job':
        # add a job
        queue_data = {'bugid' : data['bugid'],
                      'branch' : data['branch'], 'patches' : []}
        if len(data['patches']) == 0:
            queue_data['patches'] = bz.get_bug_patchset(data['bugid'])
        else:
            bug_data = bz.request('bug/%s' % data['bugid'])
            if 'attachments' not in bug_data:
                # Log error that the bug is not good
                return None
            for patch in data['patches']:
                found = False
                for attachment in bug_data['attachments']:
                    if str(attachment['id']) == str(patch):
                        patch_info = bz.get_attachment_info(attachment)
                        queue_data['patches'].append(patch_info)
                        found = True
                        break
                if not found:
                    # Log error that the patch DNE
                    print "%s Not found" % (patch)
                    return None
        print queue_data
        db.enqueue(queue_data, data['priority'])
    elif data['type'] == 'priority':
        # change a job's priority
        if not in_queue(data['bug_id']):
            # job not in queue
            pass
        else:
            change_priority('bug_id')
    elif data['type'] == 'success':
        # Mark a successful job
        pass
    elif data['type'] == 'error':
        # Mark an erroneous job
        pass

def main():
    try:
        pid = os.fork()
    except OSError, e:
        print e
        exit(1)

    if pid == 0:
        mq = mq_utils.mq_util(config['mq_host'], config['mq_exchange'])
        # make message queue our child
        mq.listen(config['mq_queue'], message_handler)
        os._exit(0)
    else:
        while(True):
            bz_search_handler()
            time.sleep(120)
            # check if child still alive. If it isn't, report & restart?
            try:
                os.waitpid(pid, os.WNOHANG)
            except OSError, e:
                if e.errno == errno.ECHILD:
                    print 'bz_searcher stopped, leave.'
                    break

if __name__ == '__main__':
    main()

