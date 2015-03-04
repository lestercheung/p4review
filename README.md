# Introcuction #

A review notification script/daemon is a program that sends out (email) notification when files/jobs are submitted to a Perforce server.

This directory contains the original Perforce review notification "daemon" and a
more serious rewrite named P4Review2.

P4Review2 is targeted for Python 2.7 and can be used with either [P4Python](http://www.perforce.com/downloads/p4python) or the command line client.


While the p4review.py is a great example to show Perforce administrators how to
implement email notification it lacks the sophistication and features that many of our
customers expects. While many Perforce admin updated the p4review.py to suit their
requirement the result is usually a highly customized solution that only works for certain environment.

Because of that,[P4Review2](http://public.perforce.com/wiki/P4Review2)
was written with customization in mind - instead of modifying the script directly
you can achieve most task by supplying a configuration isntead.


# Features #

* Authenticates against SMTP and Perforce servers with TLS/SSL
  support.

* Support unicode - even for non-ACSII characters in non-unicode
  enabled server *iff* you use a single encoding on the server.

* Configurable email templates which an be hooked with  [P4Web](http://www.perforce.com/product/components/perforce-clients?qt-perforce_graphical_tools=1#qt-perforce_graphical_tools) and [Swarm](http://www.perforce.com/product/components/swarm).

* Option to send email summary per user per invocation instead of one
  for each change.

* Configurable limits on the maximum message size and number of emails that get
  sent.

* Built-in logging and extensive command-line options to facilitate
  customization, testing and debugging.

* Ships with useful defaults which you can customize via a single INI-like configuration file so you can be up and running in a matter of minutes.

* Guards to prevent running multiple instances of the script by mistake.

* Use P4Python when available for efficiency and fallback to the Perforce command line client gracefully.

* Option for users to opt-in (--opt-in-path) reviews from P4Review2 for smooth migration from other review notification systems.



# Installation and Configuration #

Here is how to setup P4Review2 in 3 simple steps:

1. Create a configuration file using the defaults:

        python p4review2.py --sample-config > p4review2.conf

   The file is in INI-like format. Edit the file to match your environment.
   In particular, check settings for the following:

   * p4port
   * p4user
   * p4charset
   * review_counter
   * job_counter
   * change_url
   * job_url
   * user_url

   Simply set a setting to an empty string (without quotes) if it's not required.

2. Test the configuration with:

        python p4review2.py -c p4review2.conf -P

3. When ready, create a crontab (Linux/UNIX)/scheduled task (Windows)
   to run the above command without the -P option. When used with
   Windows's task scheduler you may need to create a batch file which
   calls the script with the correct command-line options.

4. Under Linux/UNIX you can also run the script as a daemon - see the *--daemon*
   and *--daemon-poll-delay* options.


## Note ##

Most (if not all) configuration can be overwritten on the command line via
options. See *python p4review2.py -h* for the complete list.

File a bug against the "lester-cheung-p4review" and start the description with "[p4review2]" if you see something missing.


# Contact #

Questions? Have an idea? You can reach me at the [Perforce
Forum](http://forums.perforce.com/index.php?/user/1195-p4lester/) or
via [Twitter (P4Lester)](https://twitter.com/p4lester).

There is also [a forum thread for P4Review2](http://forums.perforce.com/index.php?/topic/2306-p4review2).
