import ConfigParser
import urllib2, httplib
import os

HTTP_EXCEPTIONS = (urllib2.HTTPError, urllib2.URLError, httplib.BadStatusLine)

def get_configuration(conf_file):
    # load configuration
    config = ConfigParser.ConfigParser()
    config.read(conf_file)
    cfg = {}
    for section in config.sections():
        for item in config.items(section):
            if section != 'defaults':
                key = '%s_%s' % (section, item[0])
            else:
                key = item[0]
            cfg[key] = item[1]
    return cfg

def get_base_dir(path):
    return os.path.abspath(os.path.dirname(os.path.realpath(path)))

