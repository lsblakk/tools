import ldap
import urllib2
import logging

log = logging.getLogger(__name__)

class ldap_util():
    class SearchError(Exception):
        pass
    def __init__(self, host, port, bind_dn='', password=''):
        self.host = host
        self.port = port
        self.bind_dn = bind_dn
        self.password = password
        self.connection = self.__connect__()

    def __connect__(self):
        return ldap.initialize('ldap://%s:%s' % (self.host, self.port))

    def __bind__(self):
        self.connection.simple_bind(self.bind_dn, self.password)
        self.connection.result(timeout=10) # get rid of bind result

    def search(self, bind, filterstr, attrlist=None,
            scope=ldap.SCOPE_SUBTREE, retries=5):
        """
        A wrapper for ldap.search() to allow for retry on lost connection.
        Handles all connecting and binding prior to search and retries.
        Returns True on successful search and false otherwise.
        Results need to be grabbed using connection.result()

        Note that failures will be common, since connection closes at a certain
        point of inactivity, and needs to be re-established. Expect 2 attempts.
        """
        for i in range(retries):
            try:
                self.__bind__()
                self.connection.search(bind, scope,
                        filterstr=filterstr, attrlist=attrlist)
                result = self.connection.result(timeout=10)
                log.info('Success')
                return result
            except ldap.SERVER_DOWN, err:
                self.connection = self.__connect__()
                log.error('Error: %s' % (err))
                if i != retries:
                    log.info('Retrying LDAP search')
        return False

    def get_group_members(self, group):
        """
        Return a list of all members of the groups searched for.
        """
        members = []
        result = self.search('ou=groups,dc=mozilla',
                filterstr='cn=%s' % (group))
        if result == False:
            raise self.SearchError
        elif result == []:
            return []
        for group in result[1]:
            members = list(set(members) | set(group[1]['memberUid']))
        return members

    def is_member_of_group(self, mail, group):
        """
        Check if a member is in a group, or set of groups. Supports LDAP search
        strings eg. 'scm_level_*' will find members of groups of 'scm_level_1',
        'scm_level_2', and 'scm_level_3'.
        """
        members = self.get_group_members(group)

        if mail in members:
            return True
        return False

    def get_member(self, filter_, attrlist=None):
        """
        Search for member in o=com,dc=mozilla, using the given filter.
        The filter can be a properly formed LDAP query.
            see http://tools.ietf.org/html/rfc4515.html for more info.
        Some useful filers are:
            'bugzillaEmail=example@mail.com'
            'mail=example@mozilla.com'
            'sn=Surname'
            'cn=Common Name'
        attrlist can be specified as a list of attributes that should
        be returned.
        Some useful attributes are:
            bugzillaEmail
            mail
            sn
            cn
            uid
            sshPublicKey
        """
        result = self.search('o=com,dc=mozilla', filter_, attrlist)
        if result == False:
            raise self.SearchError
        elif result == []:
            return []
        return result[1]

    def get_branch_permissions(self, branch):
        """
        Queries http://hg.mozilla.org/repo-group?repo=/releases/%branch%
        for the permission level on that branch.
            eg. scm_level_3
        """
        url = 'http://hg.mozilla.org/repo-group?repo=/%s' % (branch)
        req = urllib2.Request(url)
        result = urllib2.urlopen(req)
        data = result.read()
        data = data[:-1]
        if data.find('is not an hg repository') > 0 or \
                data.find('Need a repository') > 0 or \
                data.find('A problem occurred') > 0:
            log.error('An error has occurred with branch permissions api:\n'
                      '\turl: %s\n\tresponse: %s' % (url, data))
            return None
        log.info('Required permissions for %s: %s' % (branch, data))
        return data

    def get_bz_email(self, email):
        email = self.get_member('bugzillaEmail=%s'
                % (email), ['mail'])
        try:
            email = email[0][1]['mail'][0]
        except (IndexError, KeyError):
            email = None
        return email

