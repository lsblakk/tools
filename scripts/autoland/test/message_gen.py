import sys
sys.path.append('..')
from utils.db_handler import PatchSet

run_messages = []
#RUNS
# Valid try run
run_messages.append({ 'payload': {
    'type' : 'job', 'try_run' : 1,
    'to_branch' : 0,
    'bug_id' : 10411, 'branch' : 'mozilla-central',
    'patches' : [] }})
# No try_run nor to_branch specified
run_messages.append({'payload': {
    'type' : 'job',
    'bug_id' : 10411, 'branch' : 'mozilla-central',
    'patches' : [] }})
# Not a try run nor to_branch
run_messages.append({'payload': {
    'type' : 'job',
    'try_run' : 0, 'to_branch' : 0,
    'bug_id' : 10411, 'branch' : 'branch',
    'patches' : [] }})
# Missing a whole ton of data
run_messages.append({'payload' : {
    'type' : 'job' }})

success_messages = []

#SUCCESS
# Sucessful try push
success_messages.append({'payload' : {
    'type' : 'success',
    'action' : 'try.push',
    'patchsetid' : 0,
    'bug_id' : 12345,
    'revision' : '1a2b3c4d',
    'comment' : 'Try run has started...' }})
# Successful try run
success_messages.append({'payload' : {
    'type' : 'success',
    'action' : 'try.run',
    'revision' : '1a2b3c4d' }})

# Successful branch push
success_messages.append({'payload': {
    'type' : 'branch.push',
    'patchsetid' : 0,
    'bug_id' : 12345,
    'comment' : 'successful push to branch' }})

failure_messages = []
#FAILURES
# Failed try push
failure_messages.append({'payload' : {
    'type' : 'failure',
    'action' : 'try.push',
    'patchsetid' : 1,
    'bug_id' :  12345,
    'comment' : 'failed to push to try' }})
# Failed try run
failure_messages.append({'payload' : {
    'type': 'error',
    'action' : 'try.run',
    'revision' : '2b3c4d5e' }})
# Failed patch apply
failure_messages.append({'payload' : {
    'type' : 'failure',
    'action' : 'patchset.apply',
    'patchsetid' : 1,
    'bug_id' : 12345,
    'comment' : 'failed to apply patchset' }})

messages = [run_messages, success_messages, failure_messages]

