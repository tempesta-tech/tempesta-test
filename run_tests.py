#!/usr/bin/env python2
from __future__ import print_function
import unittest
import getopt
import sys
import os
import resource
import subprocess

from helpers import tf_cfg, remote, shell, control, prepare

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017-2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

def usage():
    print("""
Functional tests for TempestaFW.

Test Framework Configuration is stored in 'tests_config.ini', Use '-d' option
to get defaults. Normally 3 machines are used to run tests: one to run HTTP
clients, second for TempestaFw it self and third one for HTTP servers. Running
tests on localhost is possible but not recommended for development environment.

Remote nodes controlled via SSH protocol. Make sure that you can be autorised by
key, not password. `ssh-copy-id` can be used for that.

-h, --help                        - Print this help and exit.
-v, --verbose                     - Enable verbose output.
-d, --defaults                    - Save defaut configuration to config file
                                    and exit.
-t, --duration <seconds>          - Duration of every single test.
-f, --failfast                    - Stop tests after first error.
-r, --resume <id>                 - Continue execution from first test matching
                                    this ID prefix
-a, --resume-after <id>           - Continue execution _after_ the first test
                                    matching this ID prefix
-n, --no-resume                   - Do not resume from state file
-l, --log <file>                  - Duplcate tests' stderr to this file
-L, --list                        - List all discovered tests subject to filters
-C, --clean                       - Stop old instances of Tempesta and Nginx
-D, --debug-files                 - Don't remove generated config files
-Z, --run-disabled                - Run only tests from list of disabled

Non-flag arguments may be used to include/exclude specific tests.
Specify a dotted-style name or prefix to include every matching test:
`cache.test_cache`, `flacky_net` (but not `sched.test_`).
Prefix an argument with `-` to exclude every matching test: `-cache.test_purge`,
`-flacky_net.test_sockets.CloseOnShutdown`.

Testsuite execution is automatically resumed if it was interrupted, or it can
be resumed manually from any given test.
""")

DISABLED_TESTS_FILE_NAME = "/tests_disabled.json"
disfile = os.path.dirname(__file__) + DISABLED_TESTS_FILE_NAME

disabled_reader = shell.DisabledListLoader(disfile)
disabled_reader.try_load()

state_reader = shell.TestState()
state_reader.load()
test_resume = shell.TestResume(state_reader)

fail_fast = False
list_tests = False
clean_old = False
run_disabled = False
prepare_tcp = True

try:
    options, remainder = getopt.getopt(sys.argv[1:], 'hvdt:fr:a:nl:LCDZp',
                                       ['help', 'verbose', 'defaults',
                                        'duration=', 'failfast', 'resume=',
                                        'resume-after=', 'no-resume', 'log=',
                                        'list', 'clean', 'debug-files',
                                        'run-disabled', 'dont-prepare'])

except getopt.GetoptError as e:
    print(e)
    usage()
    sys.exit(2)

for opt, arg in options:
    if opt in ('-f', '--failfast'):
        fail_fast = True
    if opt in ('-v', '--verbose'):
        tf_cfg.cfg.inc_verbose()
    if opt in ('-t', '--duration'):
        if not tf_cfg.cfg.set_duration(arg):
            print('Invalid option: ', opt, arg)
            usage()
            sys.exit(2)
    elif opt in ('-d', '--save'):
        tf_cfg.cfg.save_defaults()
        sys.exit(0)
    elif opt in ('-h', '--help'):
        usage()
        sys.exit(0)
    elif opt in ('-r', '--resume'):
        test_resume.set(arg)
    elif opt in ('-a', '--resume-after'):
        test_resume.set(arg, after=True)
    elif opt in ('-n', '--no-resume'):
        state_reader.drop()
    elif opt in ('-l', '--log'):
        tf_cfg.cfg.config['General']['log_file'] = arg
    elif opt in ('-L', '--list'):
        list_tests = True
    elif opt in ('-C', '--clean'):
        clean_old = True
    elif opt in ('-D', '--debug-files'):
        remote.DEBUG_FILES = True
    elif opt in ('-Z', '--run-disabled'):
        run_disabled = True
    elif opt in ('-p', '--dont-prepare'):
        prepare_tcp = False

tf_cfg.cfg.check()

# Redirect stderr into a file
tee = subprocess.Popen(
    ['tee', '-i', tf_cfg.cfg.get('General', 'log_file')],
    stdin=subprocess.PIPE,
    stdout=sys.stderr
)
sys.stderr.flush()
os.dup2(tee.stdin.fileno(), sys.stderr.fileno())
tee.stdin.close()

# Verbose level for unit tests must be > 1.
v_level = int(tf_cfg.cfg.get('General', 'Verbose')) + 1

# Install Ctrl-C handler for graceful stop.
unittest.installHandler()


#
# Discover tests, configure environment and run tests
#

# For the sake of simplicity, Unconditionally discover all tests and filter them
# afterwards instead of importing individual tests by positive filters.
loader = unittest.TestLoader()
tests = []
shell.testsuite_flatten(tests, loader.discover('.'))

root_required = False

# Root is required if too mony concurrent connections are requested
(s_limit, _) = resource.getrlimit(resource.RLIMIT_NOFILE)
# '4' multiplier is enough to start everything on one host.
min_limit = int(tf_cfg.cfg.get('General', 'concurrent_connections')) * 4
if (s_limit < min_limit):
    root_required = True
    print("Root privileges are required: too many concurrent connections.")

# Root is required if Tempesta is started locally
if tf_cfg.cfg.get('Tempesta', 'hostname') == 'localhost':
    root_required = True
    print("Root privileges are required: need access to module loading on "
          "localhost.")

if root_required:
    if os.geteuid() != 0:
        print("Please, run tests as root.")
        exit(1)
    # the default value of fs.nr_open
    nofile = 1048576
    resource.setrlimit(resource.RLIMIT_NOFILE, (nofile, nofile))


remote.connect()

# allows run tests from docker container
if prepare_tcp:
    prepare.configure()

#
# Clear garbage after previous run of test suite
#

# if we called with -C, just call tearDown for last test
if clean_old:
    if state_reader is None or state_reader.loader.last_id is None:
        tf_cfg.dbg(2, 'No test for clearing')
        sys.exit(0)
    tf_cfg.dbg(2, 'Clearing last test: %s' % state_reader.loader.last_id)
    for test in tests:
        if test.id() == state_reader.loader.last_id:
            # We don't have more information about test
            # So we can use only this
            tf_cfg.dbg(2, 'setting up')
            test.setUp()
            tf_cfg.dbg(2, 'stopping')
            test.force_stop()
            break
    state_reader.drop()
    sys.exit(0)


#
# Process exclusions/inclusions/resumption
#

# process filter arguments
use_tests = []
inclusions = []
exclusions = []

if not run_disabled:
    # remove empty arguments
    for name in remainder:
        if len(name) > 0:
            use_tests.append(name)

    for name in use_tests:
        # determine if this is an inclusion or exclusion
        if name.startswith('-'):
            name = name[1:]
            exclusions.append(name)
        else:
            inclusions.append(name)

    if disabled_reader.disable:
        for disabled in disabled_reader.disabled:
            if v_level == 0:
                tf_cfg.dbg(0, "D")
            name = disabled['name']
            reason = disabled['reason']
            tf_cfg.dbg(1, "Disabled test \"%s\" : %s" % (name, reason))
            exclusions.append(name)
else:
    for disabled in disabled_reader.disabled:
        name = disabled['name']
        reason = disabled['reason']
        tf_cfg.dbg(1, "Run disabled test \"%s\" : %s" % (name, reason))
        inclusions.append(name)
    if len(inclusions) == 0:
        tf_cfg.dbg(1, "No disabled tests, exiting")
        sys.exit()

# load resume state file, if needed
test_resume.set_filters(inclusions, exclusions)
if not test_resume:
    test_resume.set_from_file()
else:
    tf_cfg.dbg(2, 'Not resuming from file: next test specified on command line')

# Now that we initialized the loader, convert arguments to dotted form (if any).
for lst in (inclusions, exclusions):
    lst[:] = [shell.test_id_parse(loader, t) for t in lst]

test_resume.state.advance(shell.test_id_parse(loader, test_resume.state.last_id),
                          test_resume.state.last_completed)

# if the file was not used, delete it
if state_reader.has_file and not test_resume.from_file:
    state_reader.drop()

# filter testcases
resume_filter = test_resume.filter()
tests = [ t
          for t in tests
          if resume_filter(t)
          and (not inclusions or shell.testcase_in(t, inclusions))
          and not shell.testcase_in(t, exclusions) ]

#
# List tests and exit, if requested
#
if list_tests:
    for t in tests:
        print(t.id())
    sys.exit(0)

#
# Configure environment, connect to the nodes
#

addn_status = ""
if test_resume:
    if test_resume.state.last_completed:
        addn_status = " (resuming from after %s)" % test_resume.state.last_id
    else:
        addn_status = " (resuming from %s)" % test_resume.state.last_id
print("""
----------------------------------------------------------------------
Running functional tests%s...
----------------------------------------------------------------------
""" % addn_status, file=sys.stderr)


#
# Run the discovered tests
#

testsuite = unittest.TestSuite(tests)
testRunner = unittest.runner.TextTestRunner(verbosity=v_level,
                                            failfast=fail_fast,
                                            descriptions=False,
                                            resultclass=test_resume.resultclass())
result = testRunner.run(testsuite)

# check if we finished running the tests
if not tests or (test_resume.state.last_id == tests[-1].id()
                 and test_resume.state.last_completed):
    state_reader.drop()

if len(result.errors) > 0:
    sys.exit(-1)

if len(result.failures) > 0:
    sys.exit(1)

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
