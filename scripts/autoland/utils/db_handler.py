try:
    import json
except ImportError:
    import simplejson as json
from sqlalchemy import MetaData, create_engine, func
from sqlalchemy import outerjoin, or_, select, not_, and_, asc
from db_utils import PENDING, RUNNING, COMPLETE, CANCELLED, \
INTERRUPTED, MISC
from db_utils import NO_RESULT
from db_utils import get_branch_name, get_platform, get_build_type, \
get_job_type, get_revision, results_to_str, status_to_str

class DBHandler(object):

    def __init__(self, url):
        self.engine = create_engine(url)
        self.scheduler_db_meta = MetaData()
        self.scheduler_db_meta.reflect(bind=self.engine)
        self.scheduler_db_meta.bind = self.engine

    def BuildRequestsQuery(self, revision=None, branch_name=None, starttime=None, 
        endtime=None, changeid_all=True):
        """Constructs the sqlalchemy query for fetching build requests.
    
        It can return multiple rows for one build request, one for each build (if 
        the build request has multiple builds) and one for each changeid (if there 
        are multiple changes for one build request), if and only if changeid_all is 
        True. If changeid_all if False, only one changeid will be returned per 
        build request.
    
        You should use function GetBuildRequests, which groups all rows into 
        appropiate build request POPOs, and returns them as a dictionary.
    
        Input: (if any of the parameters are not specified (None), no restrictions
               will be applied for them):
               revision - sourcestamp revision, or list of revisions
               branch_name - branch name
               starttime - start time (UNIX timestamp in seconds)
               endtime - end time (UNIX timestamp in seconds)
               changeid_all - if True, the query will return 1 row per changeid, 
                    thus multiple rows for one build request; 
                    if False (the default value), only one row will be returned 
                    per build request, with only one of the changeids at random
        Output: query
        """

        b = self.scheduler_db_meta.tables['builds']
        br = self.scheduler_db_meta.tables['buildrequests']
        bs = self.scheduler_db_meta.tables['buildsets']
        s = self.scheduler_db_meta.tables['sourcestamps']
        sch = self.scheduler_db_meta.tables['sourcestamp_changes']
        c = self.scheduler_db_meta.tables['changes']

        q = outerjoin(br, b, b.c.brid == br.c.id).join(
                bs, bs.c.id == br.c.buildsetid).join(
                s, s.c.id == bs.c.sourcestampid).outerjoin(
                sch, sch.c.sourcestampid == s.c.id).outerjoin(
                c, c.c.changeid == sch.c.changeid
            ).select().with_only_columns([
                b.c.id.label('bid'),
                b.c.finish_time,
                b.c.start_time,
                br.c.id.label('brid'),
                br.c.buildername,
                br.c.buildsetid,
                br.c.claimed_at,
                br.c.complete,
                br.c.complete_at,
                br.c.results,
                bs.c.reason,
                c.c.author,
                c.c.changeid,
                c.c.comments,
                c.c.revision.label('changes_revision'),
                c.c.when_timestamp,
                s.c.branch,
                s.c.revision,
            ])
    
        if revision:
            if not isinstance(revision, list):
                revision = [revision]
            revmatcher = [s.c.revision.like(rev + '%') for rev in revision if rev]
            if revmatcher: 
                q = q.where(or_(*revmatcher))
        if branch_name:
            q = q.where(s.c.branch.like(branch_name + '%'))
        if starttime:
            q = q.where(or_(c.c.when_timestamp >= starttime, 
                br.c.submitted_at >= starttime))
        if endtime:
            q = q.where(or_(c.c.when_timestamp < endtime, 
                br.c.submitted_at < endtime))
    
        # some build requests might have multiple builds or changeids
        if not changeid_all:
            q = q.group_by(br.c.id, b.c.id)
        else:
            q = q.group_by(br.c.id, b.c.id, c.c.changeid)
    
        return q
    
    def GetBuildRequests(self, revision=None, branch_name=None, starttime=None, 
        endtime=None, changeid_all=True):
        """Fetches all build requests matching the parameters, and returns them as 
        a dictionary of build request POPOs, keyed by (br.brid, br.bid) - (build 
        request id, build id). There will be one object per build (so if one build 
        request has multiple builds, there will be more than one object).
    
        Each build request object will contain the changeids as a set of values.
    
        Input: (if any of the parameters are not specified (None), no restrictions
               will be applied for them):
               revision - sourcestamp revision, or list of revisions
               branch_name - branch name
               starttime - start time (UNIX timestamp in seconds)
               endtime - end time (UNIX timestamp in seconds)
               changeid_all - if True, the query will return 1 row per changeid, 
                    thus multiple rows for one build request; 
                    if False (the default value), only one row will be returned 
                    per build request, with only one of the changeids at random
        Output: dictionary of BuildRequest objects, keyed by (br.brid, br.bid)
        """
        q = self.BuildRequestsQuery(revision=revision, branch_name=branch_name, 
                starttime=starttime, endtime=endtime, changeid_all=changeid_all)
        connection = self.engine.connect()
        q_results = connection.execute(q)
    
        build_requests = {}
        for r in q_results:
            params = dict((str(k), v) for (k, v) in dict(r).items())
            brid, bid = params['brid'], params['bid']
            
            if (brid, bid) not in build_requests:
                build_requests[(brid, bid)] = BuildRequest(**params)
            else:
                build_requests[(brid, bid)].add_comments(params['comments'])
                build_requests[(brid, bid)].add_changeid(params['changeid'])
                build_requests[(brid, bid)].add_author(params['author'])
    
        return build_requests

    def BranchQuery(self, branch):
        """
        Returns a list of Branch objects that match the set fields in branch.
        eg. BranchQuery(Branch(threshold=50, status='disabled'))
            will return all branches in the db with a threshold of 50
            and a 'disabled' status.
        """
        r = self.scheduler_db_meta.tables['branches']
        q = r.select()
        if not isinstance(branch.id,bool): q = q.where(r.c.id.like(branch.id))
        if branch.name != False: q = q.where(r.c.name.like(branch.name))
        if branch.repo_url != False: q = q.where(r.c.repo_url.like(branch.repo_url))
        if not isinstance(branch.threshold,bool): q = q.where(r.c.threshold.like(branch.threshold))
        if branch.status != False: q = q.where(r.c.status.like(branch.status))

        connection = self.engine.connect()
        q_results = connection.execute(q)
        rows = q_results.fetchall()
        if rows:
            return map(lambda x: Branch(*x), rows)
        return None

    def BranchRunningJobsQuery(self, branch):
        """
        Returns the count of jobs running on the Branch object passed in
        """
        connection = self.engine.connect()
        r = self.scheduler_db_meta.tables['patch_sets']
        q = r.select()
        q = q.where(r.c.branch.like(branch.name))
        q = q.where(r.c.push_time != None)
        q = q.where(r.c.completion_time == None)
        q = q.count()
        count = connection.execute(q)
        return count.scalar()

    def BranchUpdate(self, branch):
        """
        Updates branches table by branch name.
        If the record is not present in the database, it is not inserted.
        Returns False on error, True otherwise.
        """
        r = self.scheduler_db_meta.tables['branches']
        if not branch.name:
            return False
        q = r.update(r.c.name.like(branch.name), branch)
        connection = self.engine.connect()
        connection.execute(q)
        return True

    def BranchInsert(self, branch):
        """
        Adds a new Branch object into the branches table.
        If that branch name is already in the table, returns False.
        """
        r = self.scheduler_db_meta.tables['branches']
        if self.BranchQuery(Branch(name=branch.name)):
            return False
        if branch.id != None:
            branch.id = None
        q = r.insert(branch)
        connection = self.engine.connect()
        result = connection.execute(q)
        return result.inserted_primary_key[0]

    def BranchDelete(self, branch):
        """
        Delete the branch corresponding to the passed branch_name
        """
        r = self.scheduler_db_meta.tables['branches']
        q = r.delete(r.c.name.like(branch.name))
        connection = self.engine.connect()
        connection.execute(q)

    def PatchSetQuery(self, patch_set):
        """
        Returns a list of PatchSet objects that match the set fields in branch.
        eg. PatchSetQuery(PatchSet(revision='revision'))
            will return all patch_sets in the db with a revision='revision'
        """
        r = self.scheduler_db_meta.tables['patch_sets']
        q = r.select()
        if patch_set.id != False:
            q = q.where(r.c.id.like(patch_set.id))
        if patch_set.bug_id != False:
            q = q.where(r.c.bug_id.like(patch_set.bug_id))
        if patch_set.author != False:
            q = q.where(r.c.author.like(patch_set.author))
        if patch_set.patches != False:
            q = q.where(r.c.patches.like(patch_set.patches))
        if patch_set.revision != False:
            q = q.where(r.c.revision.like(patch_set.revision))
        if patch_set.branch != False:
            q = q.where(r.c.branch.like(patch_set.branch))
        if patch_set.try_syntax != None:
            q = q.where(r.c.try_syntax.like(patch_set.try_syntax))
        if not isinstance(patch_set.retries, bool):
            q = q.where(r.c.retries == patch_set.retries)
        if not isinstance(patch_set.try_run, bool):
            q = q.where(r.c.try_run == patch_set.try_run)
        connection = self.engine.connect()
        q_results = connection.execute(q)
        rows = q_results.fetchall()
        if rows:
            ps = map(lambda x: PatchSet(
                id=x[0],bug_id=x[1],patches=x[2],author=x[3],retries=x[4],
                revision=x[5],branch=x[6],try_run=x[7],try_syntax=x[8],
                creation_time=x[9],push_time=x[10],completion_time=x[11]),
                rows)
            print ps
            return ps
        return None

    def PatchSetInsert(self, patch_set):
        """
        Insert the PatchSet object into the database.
        returns the inserted primary key
        """
        r = self.scheduler_db_meta.tables['patch_sets']
        connection = self.engine.connect()
        if patch_set.id != None:
            patch_set.id = None
        q = r.insert(patch_set)
        result = connection.execute(q)
        return result.inserted_primary_key[0]

    def PatchSetUpdate(self, patch_set):
        """
        Update by PatchSet.id passed in patch_set.
        """
        r = self.scheduler_db_meta.tables['patch_sets']
        if not patch_set.id:
            return False
        q = r.update(r.c.id == patch_set.id, patch_set)
        connection = self.engine.connect()
        connection.execute(q)
        return True

    def PatchSetDelete(self, patch_set):
        """
        Delete the corresponding patchset
        """
        r = self.scheduler_db_meta.tables['patch_sets']
        q = r.delete(r.c.id == patch_set.id)
        connection = self.engine.connect()
        connection.execute(q)

    def PatchSetGetNext(self, branch='%', status='enabled'):
        """
        Get the next patch_set that is queued up for a push,
        based on its creation_date, returns None if no patch_set exists
        """
        r = self.scheduler_db_meta.tables['patch_sets']
        enabled = self.BranchQuery(Branch(status='enabled'))
        if branch != '%' and branch not in map(lambda x: x.name, enabled):
            return None
        next_q = \
            '''
            SELECT DISTINCT patch_sets.id,bug_id,patches,author,retries,patch_sets.branch,try_run,try_syntax
            FROM patch_sets
            JOIN
            (
                SELECT *
                FROM branches
                LEFT OUTER JOIN
                (
                    SELECT branch,count(*) as count
                    FROM patch_sets
                    WHERE
                        NOT push_time IS NULL
                        AND completion_time IS NULL
                    GROUP BY branch
                ) as bCount
                ON branches.name=bCount.branch
                WHERE
                    branches.status='enabled'
            ) as bAvailable
            ON patch_sets.branch = bAvailable.name
            WHERE
                NOT patch_sets.creation_time IS NULL
                AND patch_sets.completion_time IS NULL
                AND patch_sets.push_time IS NULL
            ''' # This gets extended below
        # XXX: Took out the try branch is 'mozilla-central' in db - we can move a patch set into the 
        # the db for each subsequent branch
        
        b = self.BranchQuery(Branch(name='try'))
        if b == None:
            b = Branch(threshold=0)
        else:
            b = b[0]
        connection = self.engine.connect()
        # Checking to see how many try pushes are currently running
        try_count = connection.execute('''SELECT count(*) as count
                              FROM patch_sets
                              WHERE try_run=1
                              AND NOT push_time IS NULL
                              AND completion_time IS NULL''').fetchone()

        try_count = 0 if try_count == None else try_count[0]
        if try_count >= b.threshold or b.status != 'enabled':
            next_q += 'AND patch_sets.try_run = 0 '
        next_q += 'ORDER BY try_run ASC, creation_time ASC;'
        next = connection.execute(next_q).fetchone()
        if not next:
            return None
        return PatchSet(id=next[0], bug_id=next[1], patches=str(next[2]),
                author=next[3], retries=next[4], branch=next[5], try_run=next[6], try_syntax=next[7])

    def PatchSetGetRevs(self):
        """
        Get all active revisions from the patch set table.
        """
        r = self.scheduler_db_meta.tables['patch_sets']
        q = r.select().where(r.c.revision != None)
        connection = self.engine.connect()
        tmp = connection.execute(q).fetchall()
        result = []
        for t in tmp:
            result.append(t[5])
        return result

    def CommentInsert(self, cmnt):
        """
        Adds a new Comment object into the comments table.
        """
        r = self.scheduler_db_meta.tables['comments']
        if cmnt.id != None:
            cmnt.id = None
        q = r.insert(cmnt)
        connection = self.engine.connect()
        result = connection.execute(q)
        return result.inserted_primary_key[0]

    def CommentUpdate(self, cmnt):
        """
        Update by Comment.id passed in cmnt.
        """
        r = self.scheduler_db_meta.tables['comments']
        if not cmnt.id:
            return False
        q = r.update(r.c.id == cmnt.id, cmnt)
        connection = self.engine.connect()
        connection.execute(q)
        return True

    def CommentDelete(self, cmnt):
        """
        Delete the corresponding comment.
        """
        r = self.scheduler_db_meta.tables['comments']
        q = r.delete(r.c.id == cmnt.id)
        connection = self.engine.connect()
        connection.execute(q)

    def CommentGetNext(self, limit=5):
        """
        Get the next set of comments to try posting.
        Will limit the query to count number of comments.
        """
        r = self.scheduler_db_meta.tables['comments']
        q = r.select().order_by(asc(r.c.attempts)).limit(limit)
        connection = self.engine.connect()
        tmp = connection.execute(q).fetchall()
        result = []
        for t in tmp:
            result.append(Comment(id=t[0], comment=t[1], bug=t[2],
                attempts=t[3], insertion_time=t[4]))
        return result


class Branch(object):
    def __init__(self, id=False, name=False, repo_url=False,
            threshold=False, status=False):
        self.id = id
        self.name = str(name) if name else name
        self.repo_url = str(repo_url) if repo_url else repo_url
        self.threshold = threshold
        self.status = str(status) if status else status

    def __repr__(self):
        return str(self.toDict())

    def isEnabled(self):
        return self.status == 'enabled'

    def iteritems(self):
        return self.toDict().items()

    def toDict(self):
        d = {}
        if self.id != False: d['id'] = self.id
        if self.name != False: d['name'] = self.name
        if self.repo_url != False: d['repo_url'] = self.repo_url
        if not isinstance(self.threshold, bool): d['threshold'] = self.threshold
        if self.status != False: d['status'] = self.status
        return d

class PatchSet(object):
    def __init__(self, id=False, bug_id=False, patches=False, revision=False,
            branch=False, try_run=False, try_syntax=None, creation_time=False,
            push_time=False, completion_time=False, author=False, retries=False):
        import datetime, re
        self.id = id
        self.bug_id = bug_id
        # Patches needs to be a string so that sqlalchemy can insert it
        if patches:
            self.patches = re.sub('\[|\]', '', str(patches))
        else:
            self.patches = False
        self.revision = str(revision) if revision != False else revision
        self.branch = branch
        self.try_run = try_run
        self.try_syntax = try_syntax
        self.creation_time = creation_time
        self.push_time = push_time
        self.completion_time = completion_time
        self.retries = retries
        self.author = author

    def __repr__(self):
        return str(self.toDict())

    def iteritems(self):
        return self.toDict().items()

    def patchList(self):
        import re
        if not self.patches:
            return ''
        if isinstance(self.patches, list):
            return self.patches
        if isinstance(self.patches, str):
            return map(lambda x: int(x), re.split(',', self.patches))

    def toDict(self):
        import re
        d = {}
        if not isinstance(self.id,bool): d['id'] = self.id
        if self.bug_id != False: d['bug_id'] = self.bug_id
        if self.patches != False: d['patches'] = re.sub('\[|\]', '', str(self.patches))
        if self.revision != False: d['revision'] = self.revision
        if self.branch != False: d['branch'] = self.branch
        if self.try_run in (1,0): d['try_run'] = self.try_run
        if self.try_syntax != False: d['try_syntax'] = self.try_syntax
        if self.creation_time != False: d['creation_time'] = self.creation_time
        if self.push_time != False: d['push_time'] = self.push_time
        if self.completion_time != False: d['completion_time'] = self.completion_time
        if self.retries != False: d['retries'] = self.retries
        if self.author != False: d['author'] = self.author
        return d

class Comment(object):
    def __init__(self, id=False, comment=False, bug=False, attempts=1, insertion_time=False):
        self.id = id
        self.comment = comment
        self.bug = bug
        self.attempts = attempts
        self.insertion_time = insertion_time

    def __repr__(self):
        return str(self.toDict())

    def iteritems(self):
        return self.toDict().items()

    def toDict(self):
        d = {
            'id' : self.id,
            'comment' : self.comment,
            'bug' : self.bug,
            'attempts' : self.attempts,
        }
        if self.insertion_time: d['insertion_time'] = self.insertion_time
        return d

class BuildRequest(object):

    def __init__(self, author=None, bid=None, branch=None, brid=None, claimed_at=None,
        buildsetid=None, category=None, changeid=None, buildername=None,
        changes_revision=None, comments=None, complete=0, complete_at=None,
        revision=None, results=None, reason=None, submitted_at=None, finish_time=None, 
        start_time=None, when_timestamp=None):
        self.brid = brid
        self.bid = bid      # build id
        self.branch = branch
        self.branch_name = get_branch_name(branch)
        self.revision = get_revision(revision) # get at most the first 12 chars
        self.changes_revision = get_revision(changes_revision)

        self.changeid = set([changeid])
        self.when_timestamp = when_timestamp
        self.complete_at = complete_at
        self.finish_time = finish_time
        self.start_time = start_time
        self.complete = complete
        self.claimed_at = claimed_at
        self.results = results if results != None else NO_RESULT
        self.reason = reason

        self.authors = set([author])
        self.comments = set([comments])
        self.buildername = buildername
        self.buildsetid = buildsetid

        self.status = self._compute_status()

        self.platform = get_platform(buildername)
        self.build_type = get_build_type(buildername) # opt / debug
        self.job_type = get_job_type(buildername)    # build / unittest / talos

    def _compute_status(self):
        # when_timestamp & submitted_at ?
        if not self.complete and not self.complete_at and not self.finish_time:  # not complete
            if self.start_time and self.claimed_at:         # running
                return RUNNING
            if not self.start_time and not self.claimed_at: # pending
                return PENDING
        if self.complete and self.complete_at and self.finish_time and \
            self.start_time and self.claimed_at:            # complete
            return COMPLETE
        if not self.start_time and not self.claimed_at and \
            self.complete and self.complete_at and not self.finish_time:  # cancelled
            return CANCELLED
        if self.complete and self.complete_at and not self.finish_time and \
            self.start_time and self.claimed_at:
            # build interrupted (eg slave disconnected) and buildbot 
            # retriggered the build
            return INTERRUPTED

        return MISC                       # what's going on?

    def add_comments(self, comments):
        self.comments.add(comments)

    def add_changeid(self, changeid):
        self.changeid.add(changeid)

    def add_author(self, author):
        self.authors.add(author)

    def to_dict(self, summary=False):
        json_obj = {
            'brid': self.brid,
            'bid': self.bid,
            'changeid': list(self.changeid),
            'branch': self.branch,
            'branch_name': self.branch_name,
            'buildername': self.buildername,
            'revision': self.revision,
            'when_timestamp': self.when_timestamp,
            'claimed_at': self.claimed_at,
            'start_time': self.start_time,
            'complete_at': self.complete_at,
            'finish_time': self.finish_time,
            'complete': self.complete,
            'results': self.results,
            'reason': self.reason,
            'results_str': results_to_str(self.results),
            'status': self.status,
            'status_str': status_to_str(self.status),
            'authors': [auth for auth in self.authors if auth],
            'comments': [comment for comment in self.comments if comment],
            'buildsetid': self.buildsetid,
        }
        return json_obj

class Change(object):

    def __init__(self, changeid=None, revision=None, branch=None,
        when_timestamp=None, ss_revision=None):
        self.changeid = changeid
        self.revision = get_revision(revision)
        self.branch = branch
        self.when_timestamp = when_timestamp
        self.ss_revision = ss_revision  # sourcestamp revision, tentative

    def __repr__(self):
        return '%s(%s,%s)' % (self.changeid, self.branch, self.revision)

    def __str__(self):
        return self.__repr__()
