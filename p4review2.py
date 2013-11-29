#!/usr/bin/env python2.7
# -*- encoding: utf-8 -*-

'''$Id$
$Change$
$DateTime$
$Author$

This is/will be a complete rewrite of the original Perforce review
daemon.

USAGE
--------

1. Run p4review2.py --sample-config > p4review.conf

2. Edit the file p4review.conf

3. Add a crontab similar to this:

* * * * * python2.7 /path/to/p4review2.py -c /path/to/p4review.conf


FEATURES
---------

* (!!) Prevent multiple copies running concurrently with a simple lock file.

* Logging support built-in.

* Takes command-line options.

* Configurable subject and email templates.

* Can (optionally) include URLs for changelists/jobs. Examples for
  P4Web included.

* Use P4Python when available and use P4 (the CLI) as a fallback.

* Option to send a __single__ email per user per invocation instead of
  multiple ones.

* Reads config from a INI-like file using ConfigParser

* Have command line options that overrides environment variables.

* Handles unicode-enabled server **and** non-ASCII characters on a
  non-unicode-enabled server.

* Option to opt-in (--opt-in-path) reviews globally (for migration
  from old review daemon).

* Configurable URLs for changes/jobs/users (for swarm).

* Able to limit the maximum email message size with a configurable.

* SMTP auth and TLS (not SSL) support.

* Handles P4 auth (optional, not recommend!).


Nice to haves (TODOs)
-----------------------

* Include P4Web link for diffs.

* Respect protection table (for older P4D versions). See:
  http://public.perforce.com/guest/lester_cheung/p4review/p4review.py
  for a previous attempt.

* Supports hooks from the changelist description to notify additional
  users/email.

* Skip review email for change authors [done] and job modifiers
  [todo]. The later is not recorded in the job spec by default so it
  must be a configruable...

* run as a standalone daemon (UNIX and Windows). See this recipe for
  an implementation on Windows:

  http://code.activestate.com/recipes/576451-how-to-create-a-windows-service-in-python/


DISCLAIMER
-----------

User contributed content on the Perforce Public Depot is not supported
by Perforce, although it may be supported by its author. This applies
to all contributions even those submitted by Perforce employees.

If you have any comments or need any help with the content of this
particular folder, please contact support@perforce.com, and I will try
to help.

'''

import ConfigParser
import argparse
import atexit
import cgi
import email
import hashlib
import logging as log
import marshal
import os, sys
import re
import smtplib
import sqlite3
import time
import traceback

from cPickle import loads, dumps
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from getpass import getuser     # works under UNIX & Windows!
from operator import itemgetter
from pprint import pprint, pformat
from signal import SIGTERM 
from subprocess import Popen, PIPE
from textwrap import TextWrapper

## FIXME: DEBUG LEVELS (make it a configurable?)
# 0 NOTSET
# 10 DEBUG
# 20 INFO
# 30 WARN, WARNING
# 40 ERROR
# 50 CRITICAL, FATAL
DEBUGLVL = log.INFO
CFG_SECTION_NAME = 'p4review'

# Instead of changing these, store your preferences in a config file.
# See the --sample-config option.
DEFAULTS = dict(
    # General 
    log_file       = '',        # optional, but recommended
    pid_file       = os.path.join(os.path.realpath('.'), 'p4review2.pid'),
    dbfile         = ':memory:', # an (temporary) SQLite db used to
                                 # store review info from Perforce
    opt_in_path    = '',
    daemon         = '',
    poll_interval  = 300,
    # Perforce
    p4bin          = '/usr/local/bin/p4',
    p4port         = os.environ.get('P4PORT', '1666'),
    p4user         = os.environ.get('P4USER', getuser()),
    p4charset      = 'utf8',    # as P4CHARSET and to handle non-unicode server with non-ascii chars...
    p4passwd       = '',        # completely optional, best to setup ticket-based auth instead.
    review_counter = 'review',  # Perforce counter name used to keep track of last changelist notified.
    job_counter    = '',        # like review_counter but for jobs. Disabled by default. Set to 'jobreview' to enable.
    job_datefield  = 'Date',
    spec_depot     = 'spec',
    timeoffset     = 0.0,       # in hours

    # Email
    smtp_server    = 'smtp:25',
    smtp_ssl       = 'none/ssl/tls',
    smtp_user      = '',        # optional
    smtp_passwd    = '',        # optional
    summary_email  = False,
    skip_author    = True,
    max_email_size = 1024**2,   # Up to ~30MB
    max_emails     = 99,        # start small - people can choose to increase this
    max_length     = 2**12,
    default_sender = 'Perforce Review Daemon <perforce-review-daemon>', # Now we can claim to be a daemon! without guilt!
    default_domain = 'example.org',
    change_url     = 'http://p4web:1680/{chgno}?ac=10',
    job_url        = 'http://p4web:1680/{jobno}?ac=111',
    user_url       = 'http://p4web:1680/{p4user}?ac=17',
    subject_template = u'[{p4port} @{chgno}] {desc}',
    change_template  = u'''Change {chgno} by {p4user}@{p4client} on {dt}
{change_url}
{user_url}
{cldesc}
 .
Jobs updated:
{jobsupdated}
 .
Affected files:
{clfiles}
    ''',
    html_change_template = u'''
<div style="font-family: sans-serif;">
Change <a style="text-decoration: none;" href="{change_url}">{chgno}</a>
by <a style="text-decoration: none;" href="{user_url}">{p4user}</a>@{p4client}
on {dt}
<br/>
<div style="margin: 1em;">{cldesc}</div>
<br/>
Jobs updated:
<ul style="margin: 1em; padding: 0; list-style-type: none;">
{jobsupdated}
</ul>
<br/>
Affected files:
<ul style="margin-left: 1em; padding: 0; list-style-type: none;">
{clfiles}
</ul>
</div>
''',
    html_files_template = u'''<li style="margin:0; padding:0;">'''
    u'''<a style="text-decoration: none;" href="{change_url}#{fhash}">'''
    u'''{dfile}</a>#{drev} {action}</li>''',
    job_template = u'''{job_url}
{jobdesc}
    ''',
    html_job_template = u'''
<a href="{job_url}">{Job}</a>
<dl>
{jobdesc}
</dl>''',
)

def true_or_false(x):
    if x in 'FALSE OFF DISABLED DISABLE 0'.split():
        return False
    return True

def parse_args():
    import copy
    defaults = copy.deepcopy(DEFAULTS)
    confp = argparse.ArgumentParser(
        add_help=False # Turn off help, so -h works with the 2nd parser below
    )
    confp.add_argument('-c', '--config-file')
    args0, remaining_argv = confp.parse_known_args()
    
    if args0.config_file:
        cfgp = ConfigParser.SafeConfigParser()
        cfgp.read([args0.config_file])
        cfg = dict([[unicode(y, 'utf8', 'replace') for y in x] for x in cfgp.items(CFG_SECTION_NAME)])

        for key in cfg.keys():
            if not cfg[key]:
                cfg.pop(key)    # remove empty fields

        # now this is annoying - have to convert int(?) and bool types manually...
        for key in 'sample_config summary_email debug_email precached skip_author'.split():
            cfg[key] = true_or_false(cfg.get(key))
            
        for key in 'max_length max_emails max_email_size poll_interval'.split():
            if key in cfg:
                cfg[key] = float(cfg.get(key))

        for k in defaults:
            if k in cfg:
                defaults[k] = cfg.get(k)

        # Allow admins to disable change/job review in the configuration file by setting the strings below
        if defaults.get('review_counter', '').upper() in ('FALSE', '0', 'NONE', 'DISABLED', 'DISABLE', 'OFF'):
            defaults['review_counter'] = None
        if defaults.get('job_counter', '').upper() in ('FALSE', '0', 'NONE', 'DISABLED', 'DISABLE', 'OFF'):
            defaults['job_counter'] = None
        
    ap = argparse.ArgumentParser(
        description='Perforce review daemon, take 2.',
        parents=[confp],        # inherit options
        epilog='''Please send questions and comments to support@perforce.com. Share and enjoy!''')

    ap.set_defaults(**defaults)

    ap.add_argument('--sample-config', action='store_true', default=False, help='output sample config with defaults')
    ap.add_argument('-L', '--log-file', help='log file (optional)')

    ap.add_argument('-f', '--force', action='store_true', default=False,
                    help='continue even lock or output files exists')

    ap.add_argument('--daemon', help='start/stop/restart')
    ap.add_argument('--pid-file', help='stores the pid of the running p4review2 process')
    ap.add_argument('--daemon-poll-delay', type=float, help='seconds between each poll')
    
    debug = ap.add_argument_group('debug')
    debug.add_argument('-D', '--dbfile', metavar=defaults.get('dbfile'), help='name of a temp SQLite3 DB file')
    debug.add_argument('--precached', action='store_true', default=False,
                       help='data already in dbfile, not fetching from Perforce')

    p4 = ap.add_argument_group('perforce')
    p4.add_argument('-p', '--p4port', type=str, metavar=defaults.get('p4port'), help='Perforce port')
    p4.add_argument('-u', '--p4user', type=str, metavar=defaults.get('p4user'), help='Perforce review user')
    p4.add_argument('-r', '--review-counter', metavar=defaults.get('review_counter'), help='name of review counter')
    p4.add_argument('-j', '--job-counter', metavar=defaults.get('job_counter'), help='name of job counter')

    p4.add_argument('-J', '--job-datefield', metavar=defaults.get('job_datefield'),
                    help='''A job field used to determine which jobs
                    users are notified of changes to. This field needs
                    to appear in your jobspec as a "date" field with
                    persistence "always". See "p4 help jobspec" for
                    more information.''')
    
    p4.add_argument('-s', '--spec-depot', metavar=defaults.get('spec_depot'), help="name of spec depot")
    p4.add_argument('-O', '--timeoffset', type=float, help='time offsfet (in hours) between Perforce server and server running this script')
    p4.add_argument('-C', '--p4charset', metavar=defaults.get('p4charset'),
                    help='used to handle non-unicode server with non-ascii chars')
    p4.add_argument('-o', '--opt-in-path', # metavar=defaults.get('opt_in_path'),
                    help='''depot path to include in the "Review" field of user spec to opt-in review emails''')
    
    m = ap.add_argument_group('email')
    m.add_argument('--smtp', metavar=defaults.get('smtp_server'), help='SMTP server in host:port format. See smtp_ssl in config for SSL options.')
    m.add_argument('-S', '--default-sender', metavar=defaults.get('default_sender'), help='default sender email')
    m.add_argument('-d', '--default-domain', metavar=defaults.get('default_domain'), help='default domain to qualify email address without domain')
    m.add_argument('-1', '--summary-email', action='store_true', default=False, help='send one email per user')
    m.add_argument('--skip-author', type=true_or_false, metavar=defaults.get('skip_author'), help='whether to send email to changelist author')
    m.add_argument('-l', '--max-length', type=int, metavar=defaults.get('max_length'), help='limit length of data in diffent places')
    m.add_argument('-m', '--max-emails', type=int, metavar=defaults.get('max_emails'), help='maximum number of emails to be sent')
    m.add_argument('-M', '--max-email-size', type=int, metavar=defaults.get('max_email_size'), help='maximum size of email messages (in bytes)')
    m.add_argument('-P', '--debug-email', action='store_true', default=False, help='print, instead of sending email')
    m.add_argument('--change-url', metavar=defaults.get('change_url'), help='URL template to a change')
    m.add_argument('--job-url',  metavar=defaults.get('job_url'), help='URL template to a job')
    m.add_argument('--user-url', metavar=defaults.get('user_url'), help='URL template to a user')
    m.add_argument('--subject-template', metavar="'{}'".format(defaults.get('subject_template')), help='customize subject line in one-email-per-change-mode')

    args = ap.parse_args(remaining_argv)
    if 'cfgp' in locals().keys(): # we have a config parser
        args.config_file = args0.config_file
        if set(DEFAULTS.keys()) != set(cfgp.options(CFG_SECTION_NAME)) and not args.sample_config:
            log.fatal('There are changes in the configuration, please run "{} --sample-config -c <confile>" to generate a new one!'.format(sys.argv[0]))
            sys.exit(1)
    
    args.smtp_ssl = args.smtp_ssl.upper()
    return args

class P4CLI(object):
    '''Poor mans's implimentation of P4Python using P4
    CLI... just enough to support p4review2.py.

    '''
    charset = ''
    array_key_regex = re.compile(r'^(\D*)(\d*)$')
    
    def __setattr__(self, name, val):
        if name in 'port prog client charset user password'.split():
            object.__setattr__(self, name, val)

    def __getattr__(self, name):
        if name.startswith('run_'):
            p4cmd = name[4:]

            def p4runproxy(*args): # stubs for undefined run_*() functions
                cmd = [self.p4bin, '-G', '-p', self.port, '-u', self.user, p4cmd]
                if self.charset:
                    cmd = [self.p4bin, '-G', '-p', self.port, '-u', self.user, '-C', self.charset, p4cmd]
                if type(args)==tuple or type(args)==list:
                    for arg in args:
                        if type(arg) == list:
                            cmd.extend(arg)
                        else:
                            cmd.append(arg)
                else:
                    cmd += [args]
                cmd = map(str, cmd)
                p = Popen(cmd, stdout=PIPE)

                rv = []
                while 1:
                    try:
                        rv.append(marshal.load(p.stdout))
                    except EOFError:
                        break
                    except Exception as e:
                        log.error('{} {}'.format(type(e), e))
                        break

                # magic to turn fieldNNN into a list in field
                for r in rv:
                    fields_needing_cleanup = set()
                    for key in r.keys():
                        k, num = self.array_key_regex.match(key).groups()
                        if not num:
                            continue
                        r[k] = r.get(k, [])
                        r[k].append((key, r[key]))
                        fields_needing_cleanup.add(k)
                    for k in fields_needing_cleanup:
                        r[k].sort(key=lambda x: x[0])
                        r[k] = [ val[1] for val in r[k]]

                return rv
            return p4runproxy
        elif name in 'connect disconnect'.split():
            def noop():
                pass    # returns None
            return noop
        else:
            log.error(name)
            raise AttributeError

    def identify(self):
        return 'P4CLI, using {}.'.format(self.p4bin)
        
    def connected(self):
        return True

    def _p4bin(self):
        cmd = [self.p4bin] + '-G -p {} -u {} '.format(self.port, self.user).split()
        if self.charset:
            cmd += ['-C', self.charset]
        return cmd
    
    def run_login(self, *args):
        cmd = self._p4bin() + ['login']
        if '-s' in args:
            cmd += ['-s']
            proc = Popen(cmd, stdout=PIPE)
            out = proc.communicate()[0]
            if marshal.loads(out).get('code') == 'error':
                raise Exception('P4CLI exception - not logged in.')
        else:
            proc = Popen(cmd, stdin=PIPE, stdout=PIPE)
            out = proc.communicate(input=self.password)[0]
            out = '\n'.join(out.splitlines()[1:]) # Skip the password prompt...
        return [marshal.loads(out)]


class UnixDaemon(object):
    """
    A generic daemon class.
    
    Usage: subclass the Daemon class and override the run() method
    
    Source:
    http://www.jejik.com/files/examples/daemon.py
    
    Reference:
    http://www.jejik.com/articles/2007/02/a_simple_unix_linux_daemon_in_python/
    """
    def __init__(self, pidfile, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.pidfile = pidfile

    def daemonize(self):
        """
        Do the UNIX double-fork magic, see Stevens' "Advanced 
        Programming in the UNIX Environment" for details (ISBN 0201563177)
        http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
        """
        try: 
             pid = os.fork()
             if pid > 0:
                 # exit first parent
                 # sys.stderr.write('forked %d.\n' % pid)
                 sys.exit(0)
        except OSError as e: 
            sys.stderr.write("fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1)
            
        # decouple from parent environment
        os.chdir("/") 
        os.setsid() 
        os.umask(0) 

        # do second fork
        try: 
            pid = os.fork() 
            if pid > 0:
                # exit from second parent
                sys.exit(0) 
        except OSError as e: 
            sys.stderr.write("fork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1) 

        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        si = file(self.stdin, 'r')
        so = file(self.stdout, 'a+')
        se = file(self.stderr, 'a+', 0)
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

        # write pidfile
        atexit.register(self.delpid)
        pid = str(os.getpid())
        file(self.pidfile,'w+').write("%s\n" % pid)

    def delpid(self):
        os.remove(self.pidfile)

    def start(self):
         """
         Start the daemon
         """
         # Check for a pidfile to see if the daemon already runs
         try:
             pf = file(self.pidfile,'r')
             pid = int(pf.read().strip())
             pf.close()
         except IOError:
             pid = None

         if pid:
             message = "pidfile %s already exist. Daemon already running?\n"
             sys.stderr.write(message % self.pidfile)
             sys.exit(1)

         # Start the daemon
         self.daemonize()
         self.run()

    def stop(self):
         """
         Stop the daemon
         """
         # Get the pid from the pidfile
         try:
             pf = file(self.pidfile,'r')
             pid = int(pf.read().strip())
             pf.close()
         except IOError:
             pid = None

         if not pid:
             message = "pidfile %s does not exist. Daemon not running?\n"
             sys.stderr.write(message % self.pidfile)
             return # not an error in a restart

         # Try killing the daemon process	
         try:
             while 1:
                 os.kill(pid, SIGTERM)
                 time.sleep(0.1)
         except OSError as err:
             err = str(err)
             if err.find("No such process") > 0:
                 if os.path.exists(self.pidfile):
                     os.remove(self.pidfile)
             else:
                 print(str(err))
                 sys.exit(1)
                 
    def restart(self):
         """
         Restart the daemon
         """
         self.stop()
         self.start()
         
    def run(self):
         """
         You should override this method when you subclass Daemon. It will be called after the process has been
         daemonized by start() or restart().
         """
         pass

class P4ReviewDaemon(UnixDaemon):
    def __init__(self, cfg, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
        super(P4ReviewDaemon, self).__init__(cfg.pid_file, stdin=stdin, stdout=stdout, stderr=stderr)
        
    def run(self):
        '''Run P4Review in a loop with a delay'''
        while 1:
            p4review = P4Review(cfg)
            p4review.run()
            time.sleep(cfg.poll_interval)

class P4Review(object):
    # textwrapper - indented with 1 tab
    txtwrpr_indented = TextWrapper(initial_indent='\n\t', subsequent_indent='\t')
    sqlsep     = '___' # separator used in sql group_concat() function
    dtfmt      = '%Y/%m/%d:%H:%M:%S' # for jobreview counter
    html_templ = u'''<html><body>{body}</body></html>'''
    subscribed = {}    # keyed by user, whether the user opts-in for review emails
    mail_sent  = 0     # keep track of number of mails sent

    def __init__(self, cfg):
        if cfg.daemon:
            if os.path.exists(cfg.pid_file):
                pid = None
                try:
                    pid = int(open(cfg.pid_file).read().strip())
                except:
                    log.error('{} exists but does not contain a valid pid. Bailing...'.format(cfg.pid_file))
                    sys.exit(1)
                if pid != os.getpid():
                    log.error('Another p4review2 process (pid {}) is running! Bailing...'.format(pid))
                    sys.exit(1)
        else:                   # one-shot-mode
            if cfg.force and os.path.exists(cfg.pid_file):
                log.info('Removing {} on request (-f)'.format(cfg.pid_file))
                os.unlink(cfg.pid_file)
                
            if cfg.force and not cfg.precached and os.path.exists(cfg.dbfile):
                log.info('Removing {} on request (-f)'.format(cfg.dbfile))
                os.unlink(cfg.dbfile)
                
            if os.path.exists(cfg.pid_file):
                log.error('Lock file ({}) exists! Bailing...'.format(cfg.pid_file))
                sys.exit(1)
            with open(cfg.pid_file, 'w') as fd:
                fd.write('{}\n'.format(os.getpid()))
            
        self.cfg = cfg
        self.default_name, self.default_email = email.utils.parseaddr(cfg.default_sender)
        
        p4 = P4()
        p4.prog = 'P4Review2'
        p4.port = cfg.p4port
        p4.user = cfg.p4user
        p4.connect()
        
        logged_in = False
        try:
            rv = p4.run_login('-s')
            logged_in = True
        except Exception, e:
            pass
        log.debug('logged in: '+ str(logged_in))
        if not logged_in and cfg.p4passwd:
            p4.password = str(cfg.p4passwd)
            p4.run_login()
            
        if p4.run_info()[0].get('unicode') == 'enabled':
            p4.charset = str(self.cfg.p4charset)
        
        self.p4 = p4            # keep a reference for future use
        db = sqlite3.connect(cfg.dbfile,
                             detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)
        sqlite3.register_converter('spec', self.convert_spec)
        self.db = db

        if not cfg.precached:
            sqls = '''
            CREATE TABLE chg (chgno INTEGER PRIMARY KEY, pickle spec);
            CREATE TABLE job (job PRIMARY KEY, pickle spec);
            CREATE TABLE usr (usr PRIMARY KEY, name, email);
            CREATE TABLE rvw (chgno INTEGER, usr, UNIQUE(chgno, usr));
            CREATE TABLE jbrvw (job, usr, UNIQUE(job, usr));
            CREATE VIEW rvws AS SELECT usr.usr, group_concat(chgno, '{sep}') AS chgnos FROM usr LEFT JOIN rvw ON usr.usr = rvw.usr GROUP BY usr.usr;
            CREATE VIEW jbrvws AS SELECT usr.usr, group_concat(job, '{sep}') AS jobs FROM usr LEFT JOIN jbrvw ON usr.usr = jbrvw.usr GROUP BY usr.usr;
            '''.format(sep=self.sqlsep)

            db.executescript(sqls)
            db.commit()

        self.started = datetime.now() # mark the timestamp for jobreview counter
        log.info('App (pid={}) initiated.'.format(os.getpid()))

    def convert_spec(self, s):
        '''Convert a pickled server specificiation to a dictionary with unicode values.'''
        d = loads(s)
        rv = {}
        for k in d:
            if type(d[k]) == str:
                rv[k] = self.unicode(d[k])
            elif type(d[k]) == list:
                rv[k] = map(self.unicode, d[k])
            else:
                rv[k] = d[k]
        return rv
        
    def pull_data_from_p4(self):
        p4 = self.p4
        cux = self.db.cursor()

        if self.cfg.opt_in_path:
            reviewers = p4.run_reviews(self.cfg.opt_in_path)
            if not reviewers:
                log.debug('No one is subscribed to {}.'.format(self.cfg.opt_in_path))
                return          # return early if no one is subscribed to notification
            for rv in reviewers:
                self.subscribed[rv['user']] = True
                
        if self.cfg.review_counter:
            review_counter = p4.run_counter(self.cfg.review_counter)[0]['value']
            if review_counter == '0' and not self.cfg.force:
                msg = '''Review counter ({rc}) is unset. Either re-run the script with -f option or run "p4 counter {rc}" to set it.'''
                self.bail(msg.format(rc=self.cfg.review_counter))
            try:
                review_counter = int(review_counter)
            except:
                msg = '''Review counter ({}) is invalid. Run "p4 counter" to correct it.'''
                self.bail(msg.format(self.cfg.review_counter))
            log.info('Review counter ({}): {}'.format(self.cfg.review_counter, review_counter))
            
            log.info('Scraping for change review...')
            rv = p4.run_review(['-t', self.cfg.review_counter])
            log.debug('{} change(s)'.format(len(rv)))

            jobnames = set()        # so that we can pull data lazily.

            for rvw in rv:
                chgno  = rvw.get('change')
                p4user = self.unicode(rvw.get('user'))
                name   = self.unicode(rvw.get('name'))
                email  = self.unicode(rvw.get('email'))

                sql = '''INSERT OR IGNORE INTO usr (usr, name, email) values (?, ?, ?)'''
                cux.execute(sql, (p4user, name, email))

                
                # who wants to get spammed?
                rvwers = p4.run_reviews(['-c', chgno])
                if rvwers:
                    cl     = p4.run_describe(['-s', chgno])[0] # chgno is returned from "p4 review" so it must exist

                    sql = u'''insert or ignore into chg (chgno, pickle) values (?,?)'''
                    try:
                        cux.execute(sql, (chgno, dumps(
                            self.trim_dict(cl, 'chageType client user time change desc depotFile action rev job'.split()))))
                    except Exception, e:
                        log.fatal(pformat(e))
                        log.fatal(pformat(cl))
                        self.bail('kaboom!')
                    jobnames.update(cl.get('job', []))
                    
                for rvwer in rvwers:
                    usr   = self.unicode(rvwer.get('user'))
                    if self.cfg.opt_in_path: # and who doesn't want to be spammed?
                        if usr not in self.subscribed.keys():
                            continue
                    name  = self.unicode(rvwer.get('name'))
                    email = self.unicode(rvwer.get('email'))
                    sql = 'INSERT OR IGNORE INTO usr (usr, name, email) values (?,?,?)'
                    cux.execute(sql, (usr, name, email))
                    sql = 'INSERT or ignore INTO rvw (usr, chgno) values (?, ?)'
                    cux.execute(sql, (usr, chgno))

            for jobname in jobnames:
                job = p4.run_job(['-o', jobname])[0]
                cux.execute('''insert or ignore into job (job, pickle) values (?, ?)''', (jobname, dumps(self.trim_dict(job))))
        
        if self.cfg.job_counter:
            log.info('Scraping for job reviews...')
            job_counter = p4.run_counter(self.cfg.job_counter)[0].get('value')
            try:
                dt = datetime.strptime(job_counter, self.dtfmt)
            except Exception, e:
                if self.cfg.force:
                    # Not sending notifications for jobs modified before 7 days ago
                    dt = datetime.now() - timedelta(days=7) 
                else:
                    msg = '''Job review counter ({jc}) is unset or invalid ({val}). ''' \
                          '''Either re-run the script with -f option or run "p4 counter {jc} 'YYYY/mm/dd:HH:MM:SS' to set it.'''
                    self.bail(msg.format(jc=self.cfg.job_counter, val=job_counter))
            log.info('Job counter ({}): {}'.format(self.cfg.job_counter, job_counter))
                
            args = '{dfield}>{yr}/{mo}/{day}:{hr}:{min}:{sec}'.format(dfield=self.cfg.job_datefield,
                                                                      yr=dt.year,
                                                                      mo=dt.month,
                                                                      day=dt.day,
                                                                      hr=dt.hour,
                                                                      min=dt.minute,
                                                                      sec=dt.second)
            ### JOBS
            jobs = p4.run_jobs(['-e', args])
            log.debug('{} job(s)'.format(len(jobs)))
            for job in jobs:
                jobname = job.get('Job')
                
                specs = [
                    # '//depot/jobs', # this is what we use in the original review daemon, uncomment as needed (see job000032)
                    '//{}/jobs'.format(self.cfg.spec_depot),
                    '//{}/job/{}*'.format(self.cfg.spec_depot, jobname), # wildcard needed for suffixes
                ]

                rvwers = p4.run_reviews(specs)
                if rvwers:
                    # TODO: add support for job "author" (requires custom jobspec)
                    sql = '''insert or ignore into job (job, pickle) values (?,?)'''
                    self.db.execute(sql, (jobname, dumps(self.trim_dict(job))))
                    
                for rvwer in rvwers: # email, name, user
                    usr = rvwer.get('user')
                    if cfg.opt_in_path and usr not in self.subscribed.keys():
                        continue
                    name = rvwer.get('name')
                    email = rvwer.get('email')
                    sql = 'INSERT OR IGNORE INTO usr (usr, name, email) VALUES (?, ?, ?)'
                    self.db.execute(sql, (usr, name, email))
                    sql = '''INSERT OR IGNORE INTO jbrvw (job, usr) VALUES (?,?)'''
                    self.db.execute(sql, (jobname, usr))
                    
                
        self.db.commit()
        log.info('{} change review(s).'.format(self.db.execute('''select count(*) from rvw''').fetchone()[0]))
        log.info('{} job review(s).'.format(self.db.execute('''select count(*) from jbrvw''').fetchone()[0]))


    def change_summary(self, chgno):
        '''Given changeno, returns a dictionary which contains a
        subject line, change summary in text and HTML

        '''
        # log.debug('change_summary({})'.format(chgno))
        rv = self.db.execute('select pickle from chg where chgno = ?', (chgno,)).fetchall()
        assert(len(rv)==1)
        cl = rv[0][0]
        clfiles = zip( cl.get('depotFile', ['']), cl.get('rev', ['']),
                       cl.get('action', ['']) )
        cldesc = cl.get('desc').strip()

        # subject line
        subj = cfg.subject_template.format(**dict(
            p4port=self.cfg.p4port,
            chgno=chgno,
            desc=cl.get('desc')
        ))
        if len(subj) > 78: # RFC2822
            subj = subj[:75] + '...'
        cl['subject'] = subj.replace('\n', ' ')
        
        # jobs associated with this change...        
        jobs = []
        for jobname in cl.get('job', []):
            if not jobname: continue
            rv = self.db.execute('select pickle from job where job = ?', (jobname,)).fetchone()
            if rv:
                jobs.append(rv[0])
        jobs.sort(key=lambda j: j['Job'], reverse=True)
        
        # Text summary
        jobsupdated = '(none)'
        if jobs:
            jb_tmpl = u'{Job} *{Status}* {Description}'
            ujobs = []
            for job in jobs:
                j = dict()
                for k in job:
                    j[k] = job[k]
                ujobs.append(j)
            jobs = ujobs
            jobsupdated = [self.txtwrpr_indented.fill(jb_tmpl.format(**job).strip()) for job in jobs]
            jobsupdated = '\n\n'.join(jobsupdated)
        
        clfiles_txt = '(none)'
        if clfiles:
            try:
                clfiles_txt = u'\n'.join(map(lambda x: u'... {}#{} {}'.format(*x), clfiles))
            except Exception as e:
                log.error(e)
                log.error(pformat(clfiles))
        
        info = dict(
            chgno=chgno,
            p4port= self.cfg.p4port,
            p4user=cl['user'],
            p4client=cl.get('client'),
            dt=datetime.fromtimestamp(float(cl.get('time'))) + timedelta(hours=self.cfg.timeoffset),
            cldesc=self.txtwrpr_indented.fill(cldesc),
            clfiles=clfiles_txt,
            jobsupdated=jobsupdated,
            subject = subj,
        )
        info['change_url'] = self.cfg.change_url.format(**info)
        info['user_url'] = self.cfg.user_url.format(**info)
        info.update(cl)       # so we have all the stuff from the changelist

        txt_summary   = self.cfg.change_template.format(**info)

        # short circuit if no html is required.
        if not self.cfg.html_change_template:
            if len(txt_summary) > self.cfg.max_email_size:
                info['jobsupdated'] = '{} jobs...'.format(len(jobs))
                info['clfiles'] = '{} files...'.format(len(clfiles))
                txt_summary = self.cfg.change_template.format(**info)
            return cl.update(dict(text_summary=txt_summary, html_summary=None))
        
        # HTML summary
        html_info = dict()
        for key in info.keys(): # escape before html tags are added
            val = info[key]
            if type(val) == str or type(val) == unicode:
                html_info[key] = cgi.escape(val)
            elif type(val) == list:
                html_info[key] = [cgi.escape(v) for v in val]
            else:
                html_info[key] = info[key]

        html_info['cldesc'] = cgi.escape(cl.get('desc').strip())
        
        jobsupdated = '(none)'
        if jobs:
            jb_tmpl = u'<li><a style="text-decoration: none;" href="{job_url}">{Job}</a> *{Status}* {Description}</li>'
            jobsupdated = u'\n'.join([jb_tmpl.format(
                job_url=self.cfg.job_url.format(jobno=job['Job']), **job) for job in jobs])
        html_info['jobsupdated'] = jobsupdated

        clfiles_html = [
            self.cfg.html_files_template.format(
                change_url=info['change_url'],
                fhash=hashlib.md5(dfile.encode('utf8')).hexdigest(),
                dfile=cgi.escape(dfile),
                drev=drev,
                action=action
            )
            for dfile, drev, action in clfiles
        ]
        html_info['clfiles'] = u'\n'.join(clfiles_html)
        html_summary = self.cfg.html_change_template.format(**html_info)

        if len(txt_summary) + len(html_summary) > self.cfg.max_email_size:
            html_info['jobsupdated'] = info['jobsupdated'] = '{} jobs...'.format(len(jobs))
            html_info['clfiles'] = info['clfiles'] = '{} files...'.format(len(clfiles))
            txt_summary = self.cfg.change_template.format(**info)
            html_summary = self.cfg.html_change_template.format(**info)

        if len(txt_summary) + len(html_summary) > self.cfg.max_email_size:
            msg = 'Change summary for @{} exceed {} bytes after triming. Try lowering "max_length".'
            log.warn(msg.format(chgno, self.cfg.max_email_size))

        cl.update(dict(text_summary=txt_summary,
                       html_summary=html_summary))
        
        return cl
        

    def job_summary(self, jobname):
        '''Given jobname, returns a dictionary with a subject line,
        job summary in text and html

        '''
        rv = self.db.execute('select pickle from job where job = ?', (jobname,)).fetchone()
        assert(rv)              # should be true unless server has consistancy problems...
        job = rv[0]
        # add option "jobreview_subject_template"?
        subj = u'[{} {}] {}'.format(
            self.cfg.p4port, jobname,
            u' '.join(job.get('Description').strip().splitlines()))

        info = {}
        info.update(job)
        if len(subj) > 78:
            subj = subj[:75] + '...'
        subj = subj.replace('\n', ' ')
        info['subject'] = subj

        job_url = ''
        if self.cfg.job_url:
            job_url = self.cfg.job_url.format(jobno=jobname)
        info['job_url'] = job_url
        
        txt_summary, html_summary = [], []
        for key in job.keys():
            val = job.get(key).strip()
            if len(val) > self.cfg.max_length:
                val = val[:self.cfg.max_length] + '...\n(truncated)'

            txt_summary.append('\n'.join([
                '{}:'.format(key),
                self.txtwrpr_indented.fill(val)
            ]))
            html_summary.append(u'''<dt>{}</dt><dd>{}</dd>'''.format(cgi.escape(key),
                                                                    cgi.escape(val)))
        txt_summary = [self.unicode(x, encoding=self.cfg.p4charset) for x in txt_summary]
        txt_summary = u'\n\n'.join(txt_summary)
        html_summary = u'\n'.join(map(lambda x: self.unicode(x, self.cfg.p4charset), html_summary))

        info['text_summary'] = self.cfg.job_template.format(jobdesc=txt_summary, **info)
        info['html_summary'] = self.cfg.html_job_template.format(jobdesc=html_summary, **info)
        return info
        
    def send_one_email_per_change(self):
        log.debug('send_one_email_per_change()')
        def email_chg_review(rvw):
            '''helper'''
            chgno, usrs, unames, uemails = rvw
            usrs = usrs.split(self.sqlsep)
            unames = unames.split(self.sqlsep)
            uemails = uemails.split(self.sqlsep)

            aname, aemail = email.utils.parseaddr(self.cfg.default_sender)
            desc = 'no description'

            chg    = self.change_summary(chgno)
            subj   = chg['subject']
            text   = chg['text_summary']
            html   = chg['html_summary']
            author = chg['user']
            
            rv = self.db.execute('''select name, email from usr where usr = ?''', (author,)).fetchall()
            if rv:
                aname, aemail = rv[0]

            fromaddr = self.mkemailaddr((None, self.default_name, self.default_email))

            if self.cfg.skip_author and author in usrs:
                log.info('removing {} from {}'.format(author, usrs))
                idx = usrs.index(author)
                usrs.remove(author)
                unames.remove(unames[idx])
                uemails.remove(uemails[idx])
            if not usrs:        # if the list is empty, return
                return          
            toaddrs  = map(self.mkemailaddr, zip(usrs, unames, uemails))

            if html:
                msg             = MIMEMultipart('alternative')
                msg.attach(MIMEText(text, 'plain', 'utf8'))
                msg.attach(MIMEText(self.html_templ.format(body=html), 'html', 'utf8'))
            else:
                msg = MIMEText(text)
            msg['From']     = fromaddr
            msg['Reply-To'] = self.mkemailaddr((author, aname, aemail))
            msg['To']       = ', '.join(toaddrs)
            msg['Subject']  = subj
            self.sendmail(fromaddr, toaddrs, msg)

        def email_job_review(rvw):
            jobname, usrs, unames, uemails = rvw
            usrs = usrs.split(self.sqlsep)
            unames = unames.split(self.sqlsep)
            uemails = uemails.split(self.sqlsep)

            rv = self.job_summary(jobname)
            subj = rv['subject']
            text = rv['text_summary']
            html = rv['html_summary']

            if html:
                msg = MIMEMultipart('alternative')
                fr = self.mkemailaddr((None, self.default_name, self.default_email))
                msg['From'] = fr
                msg['To'] = ', '.join(map(self.mkemailaddr, zip(usrs, unames, uemails)))
                msg['Subject'] = subj
            else:
                msg = MIMEText(text)
            msg.attach(MIMEText(text, 'plain', 'utf8'))
            msg.attach(MIMEText(self.html_templ.format(body=html), 'html', 'utf8'))
            self.sendmail(msg['From'],
                          map(lambda x: '<{}>'.format(x), uemails), msg)

        # change reviews
        sql = '''SELECT chgno, group_concat(usr.usr, ?), group_concat(usr.name, ?), group_concat(usr.email, ?)
        FROM rvw, usr
        WHERE rvw.usr = usr.usr GROUP BY chgno
        '''
        chgrvws = self.db.execute(sql, (self.sqlsep,)*3).fetchall()

        # job reviews
        sql = '''SELECT job, group_concat(u.usr, ?), group_concat(u.name, ?), group_concat(u.email, ?)
        FROM jbrvw j, usr u
        WHERE j.usr = u.usr GROUP BY job;'''
        jbrvws = self.db.execute(sql, (self.sqlsep,)*3).fetchall()

        if len(chgrvws)+len(jbrvws) > self.cfg.max_emails:
            log.fatal('Will need to send {} emails, which exceed the limit of {}! Quitting.'.format(
                len(chgrvws)+len(jbrvws), self.cfg.max_emails))
            self.cleanup()
            sys.exit(1)
        
        for rvw in chgrvws:
            email_chg_review(rvw)

        for jbrvw in jbrvws:
            email_job_review(jbrvw)
        
    def send_summary_emails(self):
        log.debug('send_summary_emails()')
        def email_summary(rvw):
            usr, uname, uemail, chgnos, jobs = rvw

            if not uemail:
                log.error('No user email configured for {}, skipping'.format(usr))
                return

            chg_summaries, job_summaries = [], []

            if chgnos:
                for chgno in chgnos.split(self.sqlsep):
                    chg_summaries.append(self.change_summary(chgno))

            if jobs:
                for jobname in jobs.split(self.sqlsep):
                    job_summaries.append(self.job_summary(jobname))

            text_summaries = [csum['text_summary'] for csum in chg_summaries] + \
                             [jsum['text_summary'] for jsum in job_summaries]

            html_summaries = [csum['html_summary'] for csum in chg_summaries] + \
                             [jsum['html_summary'] for jsum in job_summaries]

            
            if not text_summaries: return # nothing to do!

            fromaddr = self.mkemailaddr((None, self.default_name, self.default_email))
            toaddr = self.mkemailaddr((usr, uname, uemail))

            if self.cfg.html_change_template:
                msg = MIMEMultipart('alternative')
                msg.attach(MIMEText('\n\n'.join(text_summaries), 'plain', 'utf8'))
                msg.attach(MIMEText(self.html_templ.format(body=u'<br/>\n'.join(html_summaries)), 'html', 'utf8'))
            else:
                msg = MIMEText('\n\n'.join(text_summaries), 'plain', 'utf8')
            msg['Subject'] = '[{}] {} changes/jobs for review'.format(self.cfg.p4port, len(text_summaries))
            msg['From'] = fromaddr
            # msg['Reply-To'] = 
            msg['To'] = toaddr
            self.sendmail(fromaddr, ['<{}>'.format(uemail)], msg)

        # FIXME: We are including changelists made by the subscriber here
        sql = u'''SELECT usr.usr, usr.name, usr.email, chgnos, jobs
        FROM rvws JOIN jbrvws ON rvws.usr=jbrvws.usr
        LEFT JOIN usr ON rvws.usr = usr.usr;'''
        
        rows = self.db.execute(sql).fetchall()
        if len(rows) > self.cfg.max_emails:
            log.fatal('Will need to send {} emails, which exceed the limit of {}! Quitting.'.format(len(rows), self.cfg.max_emails))
            self.cleanup()
            sys.exit(1)

        for rvw in rows:
            email_summary(rvw)

    ## helpers ############################################################
    def mkemailaddr(self, args):
        login, name, addr = args
        if not name:
            name = login
        if not addr:       # the email field is required so this should not
            addr = login   # happen
        if '@' not in addr:
            addr = '{}@{}'.format(addr, self.cfg.default_domain)
        return email.utils.formataddr((name, addr))

    def sendmail(self, fr, to, msg):
        if self.cfg.debug_email:
            print('ENVELOP FROM:', fr)
            print('ENVELOP TO', to)
            print(msg.as_string())
        else:
            # Note: not re-using connection to avoid timeout on the SMTP server
            # Note2: SMTP() expects a byte string, not unicode. :-/
            if self.cfg.smtp_ssl == 'SSL':
                smtp = smtplib.SMTP_SSL(* (str(self.cfg.smtp_server).split(':')) )
            else:
                smtp = smtplib.SMTP(* (str(self.cfg.smtp_server).split(':')) )
                if self.cfg.smtp_ssl == 'TLS':
                    smtp.starttls()
            if self.cfg.smtp_user and self.cfg.smtp_passwd:
                smtp.login(self.cfg.smtp_user, self.cfg.smtp_passwd)
            smtp.sendmail(fr, to, msg.as_string())
            smtp.quit()
            
        self.mail_sent += 1

    def update_review_counters(self):
        if self.cfg.debug_email:
            return              # not updating counters when debug
        reviewcounter = None
        sql = '''select max(chgno) from chg'''
        rv = self.db.execute(sql).fetchall()
        if rv:
            reviewcounter = rv[0][0]
        if reviewcounter:
            self.p4.run_counter(self.cfg.review_counter, reviewcounter)
        if self.cfg.job_counter:
            self.p4.run_counter(self.cfg.job_counter, self.started.strftime(self.dtfmt))
    
    def cleanup(self):
        if self.p4.connected():
            self.p4.disconnect()
        try:
            self.db.commit()        # just in case
        except Exception, e:
            for x in sys.exc_info():
                log.fatal(x)
            
        self.db.close()
        if not self.cfg.daemon and os.path.exists(self.cfg.pid_file):
            os.unlink(self.cfg.pid_file)
    
    def bail(self, msg):
        log.fatal(msg)
        self.cleanup()
        sys.exit(1)
    
    def unicode(self, bytestring, encoding='utf8', err='replace'):
        if type(bytestring) == type(u''):
            return bytestring
        return unicode(bytestring, encoding, err)
    
    def trim_dict(self, d, only=None):
        '''Trim data stored in a dictionary according to self.cfg.max_length'''
        maxlen = self.cfg.max_length
        newdic = {}
        for k in d.keys():
            if only and k not in only:
                continue
            val = d.get(k, '')
            if val == None:
                pass            # fail-through (and be added to newdic)
            elif type(val) == type(''):
                if len(val) > maxlen:
                    val = val[:maxlen] + '...\n(truncated after {} characters)'.format(maxlen)
            elif type(val) == type([]):
                newval = []
                for i in xrange(len(val)):
                    # append first, then check if we went over.                    
                    newval.append(val[i])
                    if sum(map(lambda x: len(x), newval)) > maxlen:
                        newval.append('... (truncated)')
                        break
                val = newval
            newdic[k] = val
        return newdic

    ## helpers ends ########################################################

    def run(self):
        dt0 = datetime.now()
        if not cfg.precached:
            self.pull_data_from_p4()
            dt1 = datetime.now()
            log.debug('... took {} pulling data from Perforce'.format(dt1 - dt0))
        dt1 = datetime.now()            

        if self.cfg.summary_email:
            self.send_summary_emails()
        else:
            self.send_one_email_per_change()
        log.info('Sent {} emails, took {}.'.format(self.mail_sent, datetime.now()-dt1))
        self.update_review_counters()
        self.cleanup()
        log.info('Started {}, finished {}, took {}.'.format(dt0, datetime.now(), datetime.now()-dt0))
        return 0

    ## Class P4Review ends here

def print_cfg(cfg):
    conf = ConfigParser.SafeConfigParser()
    conf.add_section(CFG_SECTION_NAME)
    keys = DEFAULTS.keys()
    keys.sort()
    for key in keys:
        conf.set(CFG_SECTION_NAME, key, str(cfg.__getattribute__(key)))
    conf.write(sys.stdout)
    
if __name__ == '__main__':
    cfg = parse_args()
    # NOTE: need to call log.basicCofnig() before we can use the
    # logger or it will use the default settings with level=INFO!
    if cfg.log_file:
        log.basicConfig(
            filename=cfg.log_file,
            level=DEBUGLVL,
            format='%(asctime)s %(levelname)-8s %(message)s',
            datefmt='%Y-%m-%d %H:%M',
        )
    else:
        log.basicConfig(
            stream=sys.stderr,
            level=DEBUGLVL,
            format='%(asctime)s %(levelname)-8s %(message)s',
            datefmt='%Y-%m-%d %H:%M',
        )

    log.debug('Running with Python version {}.{}.{} {} {}'.format(sys.version_info.major,
                                                                 sys.version_info.minor,
                                                                 sys.version_info.micro,
                                                                 sys.version_info.releaselevel,
                                                                 sys.version_info.serial
                                                             ))
    if cfg.sample_config:
        print(';; See --help for details...')
        print_cfg(cfg)
        sys.exit()

    if cfg.p4passwd or cfg.smtp_passwd:
        m = os.stat(cfg.config_file).st_mode
        from stat import *
        if S_IRGRP&m or S_IWGRP&m or S_IROTH&m or S_IWOTH&m:
            log.fatal('You are storing plain text password(s) in the config file with insecure permission. Fix it!')
            sys.exit(1)
    
    try:
        from P4 import P4
    except ImportError, e:
        log.warn('Using P4 CLI. Considering install P4Python for better performance. '
                 'See http://www.perforce.com/perforce/doc.current/manuals/p4script/03_python.html')
        P4 = P4CLI
        P4.p4bin = cfg.p4bin    # so all instances of P4 knows where to find the P4 binary...
    rv = 1                      # default exit value
    if cfg.daemon:
        log.info('{}ing P4Review2 in daemon mode...'.format(cfg.daemon.title()))
        app = P4ReviewDaemon(cfg)
        log.debug(cfg.daemon)
        getattr(app, cfg.daemon)() # run start/stop/restart
    else:
        app = P4Review(cfg)
        try:
            rv = app.run()
        except Exception, e:
            typ, val, tb = sys.exc_info()
            log.fatal(typ)
            log.fatal(val)
            for e in traceback.format_tb(tb):
                log.fatal(e)
            app.cleanup()
        sys.exit(rv)
