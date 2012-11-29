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

* refuse to run concurrently(!!) with a simple lock file.

* logging support built-in.

* takes command-line options.

* can optionally include a P4Web URL.

* use P4Python when available and with P4 (the CLI) as fallback.

* option to send a __single__ email per user per invocation instead of
  multiple ones.

* reads config from a ini-like file using ConfigParser

* have command line options that overrides environment varialbes.

* handles unicode-enabled server.

* option to opt-in (--opt-in-path) reviews globally (for migration from old review daemon)

* configurable URLs for changes/jobs/users (for swarm).

* configurable subject and email templates

* able to limit the maximum email message size with a configurable

* SMTP auth and TLS (not SSL) support.


Nice to haves (TODOs)
-----------------------

* handles P4 auth

* include p4web link for diffs

* From Sven: 

   > The need for a new version was born out of the necessity to catch
   > all errors [done, but need to clean up logging], enable automatic
   > logging in and re-logging in if the password is provided [todo], a
   > separate configuration file [done] and better logging [done].

* respect protection table (for older P4D versions).

* supports hooks from the changelist description to notify additional
  users/email.

* skip review email for change authors [done] and job modifiers
  [todo]. The later is not recorded in the job spec by default so it
  must be a configruable...

* run as a standalone daemon.

'''

import ConfigParser
import argparse
import cgi
import email
import hashlib
import logging as log
import os, sys
import smtplib
import sqlite3
import traceback
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from cPickle import loads, dumps
from getpass import getuser     # works under UNIX & Windows!
from operator import itemgetter
from pprint import pprint, pformat
from textwrap import TextWrapper

## DEBUG LEVELS (make it a configurable?)
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
    lock_file      = 'p4review.lock',
    log_file       = '',
    dbfile         = ':memory:', # an (temporary) SQLite db used to
                                 # store review info from Perforce
    opt_in_path    = '',

    # Perforce
    p4bin          = '/usr/local/bin/p4',
    p4port         = os.environ.get('P4PORT', '1666'),
    p4user         = os.environ.get('P4USER', getuser()),
    p4charset      = 'utf8',    # as P4CHARSET and to handle non-unicode server with non-ascii chars...
    review_counter = 'review',
    job_counter    = 'jobreview',
    job_datefield  = 'Date',
    spec_depot     = 'spec',
    timeoffset     = 0,

    # Email
    smtp_server    = 'smtp:25',
    smtp_tls       = True,
    smtp_user      = '',        # optional
    smtp_passwd    = '',        # optional
    summary_email  = False,
    max_email_size = 1024**2,   # Up to ~30MB
    max_emails     = 99,        # start small - people can choose to increase this
    max_length     = 2**12,
    default_sender = 'Review Daemon <review-daemon>', # although currently this is not a daemon. ;-)
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


def parse_args():
    import copy
    defaults = copy.deepcopy(DEFAULTS)
    confp = argparse.ArgumentParser(
        add_help=False # Turn off help, so -h works with the 2nd parser below
    )
    confp.add_argument('-c', '--config-file')
    args, remaining_argv = confp.parse_known_args()
    
    if args.config_file:
        cfgp = ConfigParser.SafeConfigParser()
        cfgp.read([args.config_file])
        cfg = dict([[unicode(y, 'utf8', 'replace') for y in x] for x in cfgp.items(CFG_SECTION_NAME)])

        for key in cfg.keys():
            if not cfg[key]:
                cfg.pop(key)    # remove empty fields
        
        # now this is annoying - have to convert int(?) and bool types manually...
        for key in 'sample_config summary_email debug_email precached smtp_tls'.split():
            if key in cfg:
                if cfg.get(key).upper() in ('FALSE', '0', ):
                    cfg[key] = False
                else:
                    cfg[key] = True
        for key in 'max_length max_emails max_email_size'.split():
            if key in cfg:
                cfg[key] = int(cfg.get(key))

        for k in defaults.keys():
            if k in cfg:
                defaults[k] = cfg.get(k)

    ap = argparse.ArgumentParser(
        description='Perforce review daemon, take 2.',
        parents=[confp],        # inherit options
        epilog='''Please send questions and comments to lcheung@perforce.com. Share and enjoy!''')

    ap.set_defaults(**defaults)

    ap.add_argument('--sample-config', action='store_true', default=False, help='output sample config with defaults')
    ap.add_argument('-L', '--log-file', help='log file (optional)')
    ap.add_argument('--lock-file', metavar=defaults.get('lock_file'),
                    help='lock file to prevent running this script concurrently')

    ap.add_argument('-D', '--dbfile', metavar=defaults.get('dbfile'), help='name of a temp SQLite3 DB file')
    ap.add_argument('-f', '--force', action='store_true', default=False,
                    help='continue even lock or output files exists')
    ap.add_argument('-o', '--opt-in-path', # metavar=defaults.get('opt_in_path'),
                    help='''depot path to include in the "Review" field of user spec to opt-in review emails''')
    ap.add_argument('--precached', action='store_true', default=False,
                    help='data already in dbfile, not fetching from Perforce (for debug)')

    p4 = ap.add_argument_group('Perforce')
    p4.add_argument('-p', '--p4port', type=str, metavar=defaults.get('p4port'), help='Perforce port')
    p4.add_argument('-u', '--p4user', type=str, metavar=defaults.get('p4user'), help='Perforce review user')
    p4.add_argument('-r', '--review-counter', metavar=defaults.get('review_counter'), help='name of review counter')
    p4.add_argument('-j', '--job-counter', metavar=defaults.get('job_counter'), help='name of job counter')

    p4.add_argument('-J', '--job-datefield', help='''A job field used
                    to determine which jobs users are notified of
                    changes to. This field needs to appear in your
                    jobspec as a "date" field with persistence
                    "always". See "p4 help jobspec" for more
                    information.

                    ''')
    
    p4.add_argument('-s', '--spec-depot', metavar=defaults.get('spec_depot'), help="name of spec depot")
    p4.add_argument('-O', '--timeoffset', type=float, help='time offsfet (in hours) between Perforce server and server running this script')
    p4.add_argument('-C', '--p4charset', help='used to handle non-unicode server with non-ascii chars')
    
    m = ap.add_argument_group('Email')
    m.add_argument('--smtp', metavar=defaults.get('smtp'), help='SMTP server in host:port format')
    m.add_argument('-S', '--default-sender', metavar=defaults.get('default_sender'), help='default sender email')
    m.add_argument('-d', '--default-domain', metavar=defaults.get('default_domain'), help='default domain to qualify email address without domain')
    m.add_argument('-1', '--summary-email', action='store_true', default=False, help='send one email per user')
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
        if len(DEFAULTS.keys()) != len(cfgp.items(CFG_SECTION_NAME)) and not args.sample_config:
            log.warning('There are changes in the configuration, please run "{} --sample-config -c <confile>" to generate a new one!'.format(sys.argv[0]))
            sys.exit(1)
    
    return args

class P4Review(object):
    # textwrapper - indented with 1 tab
    txtwrpr_indented = TextWrapper(initial_indent='\n\t', subsequent_indent='\t')
    sqlsep     = '___' # separator used in sql group_concat() function
    dtfmt      = '%Y/%m/%d:%H:%M:%S' # for jobreview counter
    html_templ = u'''<html><body>{body}</body></html>'''
    subscribed = {}    # keyed by user, whether the user opts-in for review emails
    mail_sent  = 0     # keep track of number of mails sent

    def __init__(self, cfg):
        if cfg.force and os.path.exists(cfg.lock_file):
            os.unlink(cfg.lock_file)

        if cfg.force and not cfg.precached and os.path.exists(cfg.dbfile):
            os.unlink(cfg.dbfile)
                        
        if os.path.exists(cfg.lock_file):
            log.error('Lock file ({}) exists! Bailing...'.format(cfg.lock_file))
            sys.exit(1)
            
        open(cfg.lock_file, 'w').close()

        self.cfg = cfg
        self.default_name, self.default_email = email.utils.parseaddr(cfg.default_sender)
        
        p4 = P4()
        p4.prog = 'P4Review2'
        p4.port = cfg.p4port
        p4.user = cfg.p4user
        p4.connect()
        if 'unicode' in p4.run_info()[0]:
            p4.charset = str(self.cfg.p4charset)
        self.p4 = p4            # keep a reference for future use
        db = sqlite3.connect(cfg.dbfile)
        self.db = db

        if not cfg.precached:
            sqls = '''
            CREATE TABLE chg (chgno INTEGER PRIMARY KEY, pickle);
            CREATE TABLE job (job PRIMARY KEY, pickle);
            CREATE TABLE usr (usr PRIMARY KEY, name, email);
            CREATE TABLE rvw (chgno INTEGER, usr, UNIQUE(chgno, usr));
            CREATE TABLE jbrvw (job, usr, UNIQUE(job, usr));
            CREATE VIEW rvws AS SELECT usr.usr, group_concat(chgno, '{sep}') AS chgnos FROM usr LEFT JOIN rvw ON usr.usr = rvw.usr GROUP BY usr.usr;
            CREATE VIEW jbrvws AS SELECT usr.usr, group_concat(job, '{sep}') AS jobs FROM usr LEFT JOIN jbrvw ON usr.usr = jbrvw.usr GROUP BY usr.usr;
            '''.format(sep=self.sqlsep)

            db.executescript(sqls)
            db.commit()

        self.started = datetime.now() # mark the timestamp for jobreview counter
        log.info('App initiated.')

        
    def pull_data_from_p4(self):
        p4 = self.p4
        cux = self.db.cursor()

        if self.cfg.opt_in_path:
            for rv in p4.run_reviews(self.cfg.opt_in_path):
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

            
            log.debug('scraping for change review...')
            rv = p4.run_review(['-t', self.cfg.review_counter])
            log.debug('{} change(s)'.format(len(rv)))

            jobnames = set()        # so that we can pull data lazily.

            for rvw in rv:
                chgno  = rvw.get('change')
                p4user = unicode(rvw.get('user'), self.cfg.p4charset, 'replace')
                name   = unicode(rvw.get('name'), self.cfg.p4charset, 'replace')
                email  = unicode(rvw.get('email'), self.cfg.p4charset, 'replace')

                sql = '''INSERT OR IGNORE INTO usr (usr, name, email) values (?, ?, ?)'''
                cux.execute(sql, (p4user, name, email))

                
                # who wants to get spammed?
                rvwers = p4.run_reviews(['-c', chgno])
                if rvwers:
                    cl     = p4.run_describe(['-s', chgno])[0] # chgno is returned from "p4 review" so it must exist

                    sql = u'''insert or ignore into chg (chgno, pickle) values (?,?)'''
                    try:
                        cux.execute(sql, (chgno, dumps(self.trim_dict(cl, 'chageType client user time change desc depotFile action rev job'.split()))))
                    except Exception, e:
                        log.fatal(pformat(e))
                        log.fatail(pformat(cl))
                        self.bail('kaboom!')
                    jobnames.update(cl.get('job', []))
                    
                for rvwer in rvwers:
                    usr   = unicode(rvwer.get('user') , self.cfg.p4charset, 'replace')
                    if self.cfg.opt_in_path: # and who doesn't want to be spammed?
                        if usr not in self.subscribed.keys():
                            continue
                    name  = unicode(rvwer.get('name') , self.cfg.p4charset, 'replace')
                    email = unicode(rvwer.get('email'), self.cfg.p4charset, 'replace')
                    sql = 'INSERT OR IGNORE INTO usr (usr, name, email) values (?,?,?)'
                    cux.execute(sql, (usr, name, email))
                    sql = 'INSERT or ignore INTO rvw (usr, chgno) values (?, ?)'
                    cux.execute(sql, (usr, chgno))

        for jobname in jobnames:
            job = p4.run_job(['-o', jobname])[0]
            cux.execute('''insert or ignore into job (job, pickle) values (?, ?)''', (jobname, dumps(self.trim_dict(job))))
                              
        if self.cfg.job_counter:
            log.debug('scraping for job reviews...')
            job_counter = p4.run_counter(self.cfg.job_counter)[0].get('value')
            try:
                dt = datetime.strptime(job_counter, self.dtfmt)
            except Exception, e:
                if self.cfg.force:
                    dt = datetime.now() - timedelta(days=1)                    
                else:
                    msg = '''Job review counter ({jc}) is unset or invalid ({val}). ''' \
                          '''Either re-run the script with -f option or run "p4 counter {jc} 'YYYY/mm/dd:HH:MM:SS' to set it.'''
                    self.bail(msg.format(jc=self.cfg.review_counter, val=job_counter))
                
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
                    '//depot/jobs', # this is what we use in the original review daemon
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
        log.debug('{} change review(s)'.format(self.db.execute('''select count(*) from rvw''').fetchone()[0]))
        log.debug('{} job review(s)'.format(self.db.execute('''select count(*) from jbrvw''').fetchone()[0]))


    def change_summary(self, chgno):
        '''Given changeno, returns a dictionary which contains a
        subject line, change summary in text and HTML

        '''
        rv = self.db.execute('select pickle from chg where chgno = ?', (chgno,)).fetchall()
        assert(len(rv)==1)
        cl = loads(str(rv[0][0]))
        clfiles = zip(map(lambda x: unicode(x, self.cfg.p4charset, 'replace'),
                          cl.get('depotFile', [''])),
                      cl.get('rev', ['']),
                      cl.get('action', ['']))
        cldesc = unicode(cl.get('desc').strip(), self.cfg.p4charset, 'replace')

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
        jobs = set()
        if cl.get('job'):
            for jobname in cl.get('job'):
                rv = self.db.execute('select pickle from job where job = ?', (jobname,)).fetchall()
                assert(len(rv)==1)
                job = rv[0][0]
                jobs.add(job)
        jobs = [loads(str(j)) for j in list(jobs)]
        jobs.sort(key=lambda j: j['Job'], reverse=True)

        
        # Text summary
        jobsupdated = '(none)'
        if jobs:
            jb_tmpl = u'{Job} *{Status}* {Description}'
            jobsupdated = [self.txtwrpr_indented.fill(jb_tmpl.format(**job).strip()) for job in jobs]
            jobsupdated = '\n\n'.join(jobsupdated)
        
        clfiles_txt = '(none)'
        if clfiles:
            clfiles_txt = u'\n'.join(map(lambda x: u'... {}#{} {}'.format(*x), clfiles))
        
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

        html_info['cldesc'] = cgi.escape(unicode(cl.get('desc').strip(), self.cfg.p4charset, 'replace'))
        

        jobsupdated = '(none)'
        if jobs:
            jb_tmpl = u'<li><a style="text-decoration: none;" href="{job_url}">{Job}</a> *{Status}* {Description}</li>'
            jobsupdated = u'\n'.join([jb_tmpl.format(
                job_url=self.cfg.job_url.format(jobno=job['Job']), **job) for job in jobs])
        html_info['jobsupdated'] = jobsupdated

        clfiles_html = [
            self.cfg.html_files_template.format(
                change_url=info['change_url'],
                fhash=hashlib.md5(dfile).hexdigest(),
                dfile=cgi.escape(dfile),
                drev=drev,
                action=action
            )
            for dfile, drev, action in clfiles
        ]
        html_info['clfiles'] = '\n'.join(clfiles_html)
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
        rv = self.db.execute('select pickle from job where job = ?', (jobname,)).fetchall()
        assert(len(rv) == 1)
        job = loads(str(rv[0][0]))
        subj = u'[{} {}] {}'.format(
            self.cfg.p4port, jobname,
            u' '.join(self.unicode(job.get('Description').strip(),
                                   self.cfg.p4charset, 'replace').splitlines()))

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
            val = self.unicode(job.get(key)).strip()
            if len(val) > self.cfg.max_length:
                val = val[:self.cfg.max_length] + '...\n(truncated)'
            key = self.unicode(key)

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

            fromaddr        = self.mkemailaddr((author, aname, self.default_email))
            toaddrs         = map(self.mkemailaddr, zip(usrs, unames, uemails))

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
            self.sendmail(fromaddr, ','.join(toaddrs), msg)

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
                log.info(self.cfg.default_sender)
                msg['From'] = fr
                msg['To'] = ', '.join(map(self.mkemailaddr, zip(usrs, unames, uemails)))
                msg['Subject'] = subj
            else:
                msg = MIMEText(text)
            msg.attach(MIMEText(text, 'plain', 'utf8'))
            msg.attach(MIMEText(self.html_templ.format(body=html), 'html', 'utf8'))
            self.sendmail(msg['From'],
                          ','.join(map(lambda x: '<{}>'.format(x), uemails)), msg)

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
        if '@' not in addr:
            addr = '{}@{}'.format(addr, self.cfg.default_domain)
        return email.utils.formataddr((name, addr))

    def sendmail(self, fr, to, msg):
        if self.cfg.debug_email:
            print msg.as_string()
        else:
            # Note: not re-using connection to avoid timeout on the SMTP server
            # Note2: SMTP() expects a byte string, not unicode. :-/
            smtp = smtplib.SMTP(* (str(self.cfg.smtp_server).split(':')) )
            if self.cfg.smtp_tls:
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
            # for e in traceback.format_tb(sys.exc_info()[2]):
            #     log.fatal(e)
            # traceback.print_exc()
            # pass
            
        self.db.close()
        if os.path.exists(self.cfg.lock_file):
            os.unlink(self.cfg.lock_file)
    
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
                    if sum(map(lambda x: len(x), newval)) > maxlen:
                        newval.append('... (truncated)')
                        break
                    newval.append(val[i])
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

    ## Class App ends here

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
    # logger or it will use the default settings!
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

    log.debug(cfg)
    

    if cfg.sample_config:
        print ';; See --help for details...'
        print_cfg(cfg)
        sys.exit()
    
    try:
        from P4 import P4
    except ImportError, e:
        log.warn('Using P4 CLI. Considering install P4Python for better performance. '
                 'See http://www.perforce.com/perforce/doc.current/manuals/p4script/03_python.html')
        import shlex
        from subprocess import Popen, PIPE
        import marshal

        class P4(object):
            '''Poor mans's implimentation of P4Python using P4
            CLI... just enough to support p4review2.py.

            '''
            charset = None
            user    = cfg.p4user
            port    = cfg.p4port
            p4bin   = cfg.p4bin

            def __setattr__(self, name, val):
                if name in 'port prog client charset user'.split():
                    object.__setattr__(self, name, val)

            def __getattr__(self, name):
                if name.startswith('run_'):
                    p4cmd = name[4:]
                    def p4run(*args):
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
                            except:
                                break
                        return rv
                    return p4run
                elif name in 'connect disconnect'.split():
                    def noop():
                        pass    # returns None
                    return noop

            def connected(self):
                return True
        
    app = P4Review(cfg)
    rv = 1                      # default exit value
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
