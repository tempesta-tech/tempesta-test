#!/usr/bin/env python3
from __future__ import print_function

import gc
import getopt
import inspect
import os
import re
import resource
import subprocess
import sys
import time
import unittest
from importlib.machinery import SourceFileLoader

import inquirer
import psutil

import run_config
from framework import tester
from helpers import output_interceptor, prepare, remote, shell, tf_cfg, util

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"


sys.stdout = output_interceptor.stdout_inter
sys.stderr = output_interceptor.stderr_inter


def usage():
    print(
        """
Functional tests for TempestaFW.

Test Framework Configuration is stored in 'tests_config.ini', Use '-d' option
to get defaults. Normally 3 machines are used to run tests: one to run HTTP
clients, second for TempestaFw it self and third one for HTTP servers. Running
tests on localhost is possible but not recommended for development environment.

Remote nodes controlled via SSH protocol. Make sure that you can be autorised by
key, not password. `ssh-copy-id` can be used for that.

-h, --help                        - Print this help and exit.
-v, --verbose <level>             - Enable verbose output.
-H, --choice                      - Choose test by file path. You must provide
                                    file path instead of test name in that case.
-F, --from-failstr                - Convert unittest fail message to test name.
                                    You must provide fail message instead of
                                    test name in that case.
-d, --defaults                    - Save default configuration to config file
                                    and exit.
-t, --duration <seconds>          - Duration of every single test.
-f, --failfast                    - Stop tests after first error.
-r, --resume <id>                 - Continue execution from first test matching
                                    this ID prefix
-E, --retry                       - Retry failed tests, listed in tests_retry file
-R, --repeat <N>                  - Repeat every test for N times
-a, --resume-after <id>           - Continue execution _after_ the first test
                                    matching this ID prefix
-m, --check-memory-leaks          - Check memory leaks for each test                                    
-n, --no-resume                   - Do not resume from state file
-l, --log <file>                  - Duplcate tests' stderr to this file
-L, --list                        - List all discovered tests subject to filters
-C, --clean                       - Stop old instances of Tempesta and Nginx
-D, --debug-files                 - Don't remove generated config files
-Z, --run-disabled                - Run only tests from list of disabled
-I, --ignore-errors               - Don't exit on import/syntax errors in tests
-s, --save-tcpdump                - Enable tcpdump for test. Results is saved to
                                    file with name of test. Works with -R option.
                                    Default path: /var/tcpdump/<date>/<time>/<test_name>.pcap [number].
                                    For -i option - /<identifier>/<test_id>.pcap [number]
-i, --identifier <id>             - Path to tcpdump results folder. Workspace path
                                    and build tag on CI or other.
-S, --save-secrets                - Save TLS secrets for deproxy and curl client to
                                    secrets.txt in main directory.
-T, --tcp-segmentation <size>     - Run all tests with TCP segmentation. It works for
                                    deproxy client and server.

Non-flag arguments may be used to include/exclude specific tests.
Specify a dotted-style name or prefix to include every matching test:
`cache.test_cache`, `flacky_net` (but not `sched.test_`).
Prefix an argument with `-` to exclude every matching test: `-cache.test_purge`,
`-flacky_net.test_sockets.CloseOnShutdown`.

Testsuite execution is automatically resumed if it was interrupted, or it can
be resumed manually from any given test.
"""
    )


def choose_test(file_path):
    module_name = re.sub("\.py$", "", file_path).replace(os.sep, ".")
    module = SourceFileLoader(module_name, file_path).load_module()
    classes = dict(inspect.getmembers(module, predicate=inspect.isclass))

    q = inquirer.List("class", message="Select test class", choices=classes.keys())
    class_name = inquirer.prompt([q])["class"]

    methods = [
        name
        for name, obj in inspect.getmembers(classes[class_name])
        if inspect.isfunction(obj) and name.startswith("test_")
    ]
    q = inquirer.List("method", message="Select test method", choices=["ALL"] + methods)
    method_name = inquirer.prompt([q])["method"]

    full_test_name = f"{module_name}.{class_name}"
    if method_name != "ALL":
        full_test_name += f".{method_name}"

    return full_test_name


def test_from_failstr(failstr):
    m = re.match("^[A-Z]+: ([a-z0-9_]+) \((.+)\)", failstr)
    return f"{m.group(2)}.{m.group(1)}"


DISABLED_TESTS_FILE_NAME = "/tests_disabled.json"
disfile = os.path.dirname(__file__) + DISABLED_TESTS_FILE_NAME

# this file is needed for tests with TCP segmentation
DISABLED_TESTS_FILE_NAME_TCP_SEG = "/tests_disabled_tcpseg.json"
disfile_tcp_seg = os.path.dirname(__file__) + DISABLED_TESTS_FILE_NAME_TCP_SEG

# this file is needed for tests with remote config
DISABLED_TESTS_FILE_NAME_REMOTE = "/tests_disabled_remote.json"
disfile_remote = os.path.dirname(__file__) + DISABLED_TESTS_FILE_NAME_REMOTE

TESTS_PRIORITY_FILE_NAME = "/tests_priority"
priority_file = os.path.dirname(__file__) + TESTS_PRIORITY_FILE_NAME
t_priority_out = open(priority_file).readlines()
t_priority_out.reverse()

RETRY_FILE_NAME = "/tests_retry"
bestoff_file = os.path.dirname(__file__) + RETRY_FILE_NAME
t_retry_out = open(bestoff_file).readlines()

disabled_reader = shell.DisabledListLoader(disfile)
disabled_reader.try_load()

disabled_reader_tcp_seg = shell.DisabledListLoader(disfile_tcp_seg)
disabled_reader_tcp_seg.try_load()

disabled_reader_remote = shell.DisabledListLoader(disfile_remote)
disabled_reader_remote.try_load()

state_reader = shell.TestState()
state_reader.load()
test_resume = shell.TestResume(state_reader)

fail_fast = False
list_tests = False
clean_old = False
run_disabled = False
prepare_tcp = True
n_count = 1
ignore_errors = False
t_retry = False

try:
    options, testname_args = getopt.getopt(
        sys.argv[1:],
        "hv:HFdt:T:fr:ER:a:nl:LCDZpPIi:sSm",
        [
            "help",
            "verbose=",
            "from-failstr",
            "choice",
            "defaults",
            "duration=",
            "failfast",
            "resume=",
            "retry",
            "resume-after=",
            "repeat=",
            "no-resume",
            "log=",
            "list",
            "clean",
            "debug-files",
            "run-disabled",
            "dont-prepare",
            "ignore-errors",
            "identifier=",
            "save-tcpdump",
            "save-secrets",
            "tcp-segmentation=",
            "disable-auto-parser",
        ],
    )
    testname_args = filter(None, testname_args)

except getopt.GetoptError as e:
    print(e)
    usage()
    sys.exit(2)

for opt, arg in options:
    if opt in ("-f", "--failfast"):
        fail_fast = True
    if opt in ("-v", "--verbose"):
        tf_cfg.cfg.set_v_level(arg)
    if opt in ("-H", "--choice"):
        testname_args = list(map(choose_test, testname_args))
        tf_cfg.dbg(6, f"Tests chosen: {testname_args}")
    if opt in ("-F", "--from-failstr"):
        testname_args = list(map(test_from_failstr, testname_args))
        tf_cfg.dbg(6, f"Tests from fail strings: {testname_args}")
    if opt in ("-t", "--duration"):
        if not tf_cfg.cfg.set_duration(arg):
            print("Invalid option: ", opt, arg)
            usage()
            sys.exit(2)
    elif opt in ("-d", "--save"):
        tf_cfg.cfg.save_defaults()
        sys.exit(0)
    elif opt in ("-h", "--help"):
        usage()
        sys.exit(0)
    elif opt in ("-r", "--resume"):
        test_resume.set(arg)
    elif opt in ("-a", "--resume-after"):
        test_resume.set(arg, after=True)
    elif opt in ("-n", "--no-resume"):
        state_reader.drop()
    elif opt in ("-l", "--log"):
        tf_cfg.cfg.config["General"]["log_file"] = arg
    elif opt in ("-L", "--list"):
        list_tests = True
    elif opt in ("-C", "--clean"):
        clean_old = True
    elif opt in ("-R", "--repeat"):
        n_count = arg
    elif opt in ("-E", "--retry"):
        t_retry = True
    elif opt in ("-D", "--debug-files"):
        remote.DEBUG_FILES = True
    elif opt in ("-Z", "--run-disabled"):
        run_disabled = True
    elif opt in ("-p", "--dont-prepare"):
        prepare_tcp = False
    elif opt in ("-I", "--ignore-errors"):
        ignore_errors = True
    elif opt in ("-i", "--identifier"):
        tester.build_path = arg
    elif opt in ("-s", "--save-tcpdump"):
        tester.save_tcpdump = True
        run_config.SAVE_SECRETS = True
    elif opt in ("-S", "--save-secrets"):
        run_config.SAVE_SECRETS = True
    elif opt in ("-T", "--tcp-segmentation"):
        if int(arg) > 0:
            run_config.TCP_SEGMENTATION = int(arg)
        else:
            raise ValueError("tcp-segmentation argument must be greater than 0.")
    elif opt in ("-P", "--disable-auto-parser"):
        run_config.AUTO_PARSER = False
    elif opt in ("-m", "--check-memory-leaks"):
        run_config.CHECK_MEMORY_LEAKS = True

tf_cfg.cfg.check()

# Redirect stderr into a file
tee = subprocess.Popen(
    ["tee", "-i", tf_cfg.cfg.get("General", "log_file")],
    stdin=subprocess.PIPE,
    stdout=output_interceptor.stderr_inter.origin,
)
sys.stderr.flush()
os.dup2(
    tee.stdin.fileno(),
    output_interceptor.stderr_inter.origin.fileno(),
)
tee.stdin.close()

# Verbose level for unit tests must be > 1.
v_level = int(tf_cfg.cfg.get("General", "Verbose")) + 1

# Install Ctrl-C handler for graceful stop.
unittest.installHandler()


#
# Discover tests, configure environment and run tests
#

# For the sake of simplicity, Unconditionally discover all tests and filter them
# afterwards instead of importing individual tests by positive filters.
loader = unittest.TestLoader()
tests = []
shell.testsuite_flatten(tests, loader.discover("."))

if len(loader.errors) > 0:
    print(
        "\n"
        "----------------------------------------------------------------------\n"
        "There were errors during tests discovery stage...\n"
        "----------------------------------------------------------------------\n",
        file=sys.stderr,
    )
    # runner.TextTestRunner can print import or syntax errors, however,
    # the failed modules will be filtered out like they never existed.
    # So we have to explicitly find and print those errors.
    for error in loader.errors:
        print(error)

    if not ignore_errors:
        sys.exit(1)


root_required = False

# Root is required if too mony concurrent connections are requested
(s_limit, _) = resource.getrlimit(resource.RLIMIT_NOFILE)
# '4' multiplier is enough to start everything on one host.
min_limit = int(tf_cfg.cfg.get("General", "concurrent_connections")) * 4
if s_limit < min_limit:
    root_required = True
    print("Root privileges are required: too many concurrent connections.")

# Root is required if Tempesta is started locally
if tf_cfg.cfg.get("Tempesta", "hostname") == "localhost":
    root_required = True
    print("Root privileges are required: need access to module loading on " "localhost.")

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
        tf_cfg.dbg(2, "No test for clearing")
        sys.exit(0)
    tf_cfg.dbg(2, "Clearing last test: %s" % state_reader.loader.last_id)
    for test in tests:
        if test.id() == state_reader.loader.last_id:
            # We don't have more information about test
            # So we can use only this
            tf_cfg.dbg(2, "setting up")
            test.setUp()
            tf_cfg.dbg(2, "stopping")
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

if run_config.TCP_SEGMENTATION and disabled_reader_tcp_seg.disable:
    disabled_reader.disabled.extend(disabled_reader_tcp_seg.disabled)

if (
    type(remote.host) is remote.RemoteNode
    or type(remote.client) is remote.RemoteNode
    or type(remote.tempesta) is remote.RemoteNode
    or type(remote.server) is remote.RemoteNode
) and disabled_reader_remote.disable:
    disabled_reader.disabled.extend(disabled_reader_remote.disabled)

if not run_disabled:
    use_tests = [re.sub("\.py$", "", arg).replace(os.sep, ".") for arg in testname_args]
    for name in use_tests:
        # determine if this is an inclusion or exclusion
        if name.startswith("-"):
            name = name[1:]
            exclusions.append(name)
        else:
            inclusions.append(name)

    if disabled_reader.disable:
        for disabled in disabled_reader.disabled:
            if v_level == 0:
                tf_cfg.dbg(0, "D")
            name = disabled["name"]
            reason = disabled["reason"]
            tf_cfg.dbg(6, 'Disabled test "%s" : %s' % (name, reason))
            exclusions.append(name)
else:
    for disabled in disabled_reader.disabled:
        name = disabled["name"]
        reason = disabled["reason"]
        tf_cfg.dbg(1, 'Run disabled test "%s" : %s' % (name, reason))
        inclusions.append(name)
    if len(inclusions) == 0:
        tf_cfg.dbg(1, "No disabled tests, exiting")
        sys.exit()

# load resume state file, if needed
test_resume.set_filters(inclusions, exclusions)
if not test_resume:
    test_resume.set_from_file()
else:
    tf_cfg.dbg(2, "Not resuming from file: next test specified on command line")

# Now that we initialized the loader, convert arguments to dotted form (if any).
for lst in (inclusions, exclusions):
    lst[:] = [shell.test_id_parse(loader, t) for t in lst]

test_resume.state.advance(
    shell.test_id_parse(loader, test_resume.state.last_id), test_resume.state.last_completed
)

# if the file was not used, delete it
if state_reader.has_file and not test_resume.from_file:
    state_reader.drop()

# Sort tests by priority
for p in t_priority_out:
    for t in tests:
        if t.id().startswith(p.rstrip()):
            tests.insert(0, tests.pop(tests.index(t)))

if t_retry:
    # Create list of tests which can be retried
    retry_tests = []
    for t_ret in t_retry_out:
        for t in tests:
            if t.id().startswith(t_ret.rstrip()):
                retry_tests.append(t)

# filter testcases
resume_filter = test_resume.filter()
tests = [
    t
    for t in tests
    for _ in range(int(n_count))
    if resume_filter(t)
    and (not inclusions or shell.testcase_in(t, inclusions))
    and not shell.testcase_in(t, exclusions)
]


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
if n_count != 1:
    addn_status = f" for {n_count} times each"
used_memory_before = util.get_used_memory()
python_memory_before = psutil.Process().memory_info().rss // 1024

print(
    """
----------------------------------------------------------------------
Running functional tests%s...
----------------------------------------------------------------------
"""
    % addn_status,
    file=sys.stderr,
)


#
# Run the discovered tests
#

testsuite = unittest.TestSuite(tests)
testRunner = unittest.runner.TextTestRunner(
    verbosity=v_level, failfast=fail_fast, descriptions=False, resultclass=test_resume.resultclass()
)
result = testRunner.run(testsuite)

if t_retry:
    rerun_tests = []
    for err in result.errors:
        if err[0] in retry_tests:
            retry_tests.pop(retry_tests.index(err[0]))
            rerun_tests.append(err[0])
    for err in result.failures:
        if err[0] in retry_tests:
            retry_tests.pop(retry_tests.index(err[0]))
            rerun_tests.append(err[0])
    if len(rerun_tests) > 0:
        print(
            """
----------------------------------------------------------------------
Run failed tests again ...
----------------------------------------------------------------------
"""
        )
        re_testsuite = unittest.TestSuite(rerun_tests)
        re_testRunner = unittest.runner.TextTestRunner(
            verbosity=v_level,
            failfast=fail_fast,
            descriptions=False,
            resultclass=test_resume.resultclass(),
        )
        re_result = re_testRunner.run(re_testsuite)

        for err in result.errors:
            if err not in re_result.errors:
                index = result.errors.index(err)
                out = result.errors.pop(index)
        for fail in result.failures:
            if fail not in re_result.failures:
                index = result.failures.index(fail)
                out = result.failures.pop(index)

# check if we finished running the tests
if not tests or (test_resume.state.last_id == tests[-1].id() and test_resume.state.last_completed):
    state_reader.drop()

# check a memory consumption after all tests
gc.collect()
time.sleep(1)
python_memory_after = psutil.Process().memory_info().rss // 1024
delta_python = python_memory_after - python_memory_before

used_memory_after = util.get_used_memory()
memleak_msg = (
    "Check memory leaks for test suite:\n"
    f"Before: used memory: {used_memory_before};\n"
    f"Before: python memory: {python_memory_before};\n"
    f"After: used memory: {used_memory_after};\n"
    f"After: python memory: {python_memory_after}"
)
tf_cfg.dbg(2, memleak_msg)
if run_config.CHECK_MEMORY_LEAKS:
    assert (
        used_memory_after - delta_python - used_memory_before <= run_config.MEMORY_LEAK_THRESHOLD
    ), memleak_msg

if len(result.errors) > 0:
    sys.exit(-1)

if len(result.failures) > 0:
    sys.exit(1)

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
