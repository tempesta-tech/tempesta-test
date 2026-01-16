#!/usr/bin/env python3

import sys

# we use `asyncore` that was removed from 3.12
if sys.version_info.major != 3 or sys.version_info.minor > 11:
    sys.stderr.write(
        "Python version is not supported: required major is `3`, minor is till `11`, i.e. 3.12 is not supported\n",
    )
    sys.exit(1)

import getopt
import inspect
import os
import re
import resource
import unittest
from importlib.machinery import SourceFileLoader

import inquirer

import run_config
from framework import tempesta
from helpers import error, memworker, remote, tf_cfg
from test_suite import prepare, shell, tester
from test_suite.tester import test_logger

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


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
    --info                        - Set INFO level for stream handler in logging
    --debug                       - Set DEBUG level for stream handler in logging
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
    --kernel-dbg                  - Run tests for the kernel with sanitizers and checkers.
                                    You should use this option carefully because the tests
                                    take a very long time.
-T, --tcp-segmentation <size>     - Run all tests with TCP segmentation. It works for
                                    deproxy client and server.

Non-flag arguments may be used to include/exclude specific tests.
Specify a dotted-style name or prefix to include every matching test:
`cache.test_cache`, `t_server_connections` (but not `sched.test_`).
Prefix an argument with `-` to exclude every matching test: `-cache.test_purge`,
`-t_server_connections.test_sockets.CloseOnShutdown`.

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


def __check_kmemleak() -> None:
    """Check kmemleak result if `--kernel-dbg` option is present."""
    if run_config.KERNEL_DBG_TESTS:
        # we should run TempestaFW again to display the output correctly
        tfw = tempesta.Tempesta(vhost_auto=False)
        tfw.config.set_defconfig("")
        tfw.check_config = False
        tfw.start()

        try:
            remote.tempesta.run_cmd("echo scan > /sys/kernel/debug/kmemleak", timeout=60)
            stdout, stderr = remote.tempesta.run_cmd("cat /sys/kernel/debug/kmemleak", timeout=60)
            kmemleak_msg = (
                (
                    "kmemleak result.\n"
                    "----------------------------------------------------------------------------\n"
                    f"{stdout.decode()}\n"
                    "----------------------------------------------------------------------------\n"
                )
                if stdout
                else "/sys/kernel/debug/kmemleak is empty"
            )
            test_logger.critical(kmemleak_msg)
            if b"tfw_" in stdout:
                raise error.KmemLeakException(stdout=stdout.decode())
        finally:
            tfw.stop()


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
        "h:HFd:t:T:fr:ER:a:nl:LCDZpPIi:sSm",
        [
            "help",
            "info",
            "debug",
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
            "save-config=",
            "save-tcpdump",
            "save-secrets",
            "kernel-dbg",
            "tcp-segmentation=",
            "disable-auto-parser",
        ],
    )
    testname_args = filter(None, testname_args)

except getopt.GetoptError as e:
    print(e)
    usage()
    sys.exit(2)

# unitests verbosity level
v_level = 2

for opt, arg in options:
    if opt in ("-f", "--failfast"):
        fail_fast = True
    elif opt == "--info":
        tf_cfg.cfg.set_option(section="Loggers", opt="stream_handler", value="INFO")
        v_level = 0
    elif opt == "--debug":
        tf_cfg.cfg.set_option(section="Loggers", opt="stream_handler", value="DEBUG")
        v_level = 0
    elif opt in ("-H", "--choice"):
        testname_args = list(map(choose_test, testname_args))
        test_logger.debug(f"Tests chosen: {testname_args}")
    elif opt in ("-F", "--from-failstr"):
        testname_args = list(map(test_from_failstr, testname_args))
        test_logger.debug(f"Tests from fail strings: {testname_args}")
    elif opt in ("-t", "--duration"):
        if not tf_cfg.cfg.set_duration(arg):
            print("Invalid option: ", opt, arg)
            usage()
            sys.exit(2)
    elif opt in ("-d", "--save-config"):
        if arg not in ["local", "remote"]:
            raise ValueError(
                "You must declare the type of setup (local or remote).\n "
                "The remote setup is used for CI, do not use it for yourself.\n"
            )
        tf_cfg.cfg.save_defaults(arg)
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
        n_count = int(arg)
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
    elif opt == "--kernel-dbg":
        run_config.KERNEL_DBG_TESTS = True
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
tf_cfg.cfg.configure_logger()

t_priority_out = open(os.path.join("tests_priority")).readlines()
t_priority_out.reverse()

t_retry_out = open(os.path.join("tests_retry")).readlines()

# this file is needed for tests with local config
disabled_reader = shell.DisabledListLoader(os.path.join("tests_disabled.json"))
# this file is needed for tests with TCP segmentation
disabled_reader_tcp_seg = shell.DisabledListLoader(os.path.join("tests_disabled_tcpseg.json"))
# this file is needed for tests with remote config
disabled_reader_remote = shell.DisabledListLoader(os.path.join("tests_disabled_remote.json"))
# this file is needed for tests with the debug kernel
disabled_reader_dbg_kernel = shell.DisabledListLoader(os.path.join("tests_disabled_dbgkernel.json"))

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

if run_config.KERNEL_DBG_TESTS:
    try:
        remote.tempesta.run_cmd("cat /sys/kernel/debug/kmemleak")
    except error.ProcessBadExitStatusException as es_exs:
        kml_err_msg = "kmemleak is possibly disabled. Please enable kmemleak or not use `--kernel-dbg` option."
        test_logger.critical(kml_err_msg)
        raise error.KmemLeakException(kml_err_msg) from es_exs


# allows run tests from docker container
if prepare_tcp:
    prepare.configure_tcp()

#
# Clear garbage after previous run of test suite
#

# if we called with -C, just call tearDown for last test
if clean_old:
    if state_reader is None or state_reader.loader.last_id is None:
        test_logger.info("No test for clearing")
        sys.exit(0)
    test_logger.info(f"Clearing last test: {state_reader.loader.last_id}")
    for test in tests:
        if test.id() == state_reader.loader.last_id:
            # We don't have more information about test
            # So we can use only this
            test.setUp()
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

if isinstance(remote.tempesta, remote.RemoteNode) and disabled_reader_remote.disable:
    disabled_reader.disabled.extend(disabled_reader_remote.disabled)

if run_config.KERNEL_DBG_TESTS and disabled_reader_dbg_kernel.disable:
    disabled_reader.disabled.extend(disabled_reader_dbg_kernel.disabled)

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
            name = disabled["name"]
            reason = disabled["reason"]
            test_logger.debug(f'Disabled test name" : {reason}')
            exclusions.append(name)
else:
    for disabled in disabled_reader.disabled:
        name = disabled["name"]
        reason = disabled["reason"]
        test_logger.info(f'Run disabled test "{name}" : {reason}')
        inclusions.append(name)
    if len(inclusions) == 0:
        test_logger.warning("No disabled tests, exiting")
        sys.exit()

# load resume state file, if needed
test_resume.set_filters(inclusions, exclusions)
if not test_resume:
    test_resume.set_from_file()
else:
    test_logger.warning("Not resuming from file: next test specified on command line")

# Now that we initialized the loader, convert arguments to dotted form (if any).
for lst in (inclusions, exclusions):
    lst[:] = [shell.test_id_parse(loader, t) for t in lst]

test_resume.state.advance(
    shell.test_id_parse(loader, test_resume.state.last_id), test_resume.state.last_completed
)

# if the file was not used, delete it
if state_reader.has_file and not test_resume.from_file:
    state_reader.drop()

# filter testcases
resume_filter = test_resume.filter()

filtered_tests = []
for t in tests:
    if (
        resume_filter(t)
        and (not inclusions or shell.testcase_in(t, inclusions))
        and not shell.testcase_in(t, exclusions)
    ):
        filtered_tests.append(t)

# Repeat the tests according to the `-R` option
tests = []
for t in filtered_tests:
    for _ in range(int(n_count)):
        tests.append(t)

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

if run_config.KERNEL_DBG_TESTS:
    remote.tempesta.run_cmd("echo clear > /sys/kernel/debug/kmemleak")

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
with memworker.check_memory_leaks():
    testsuite = unittest.TestSuite(tests)
    testRunner = unittest.runner.TextTestRunner(
        verbosity=v_level,
        failfast=fail_fast,
        descriptions=False,
        resultclass=test_resume.resultclass(),
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
    if not tests or (
        test_resume.state.last_id == tests[-1].id() and test_resume.state.last_completed
    ):
        state_reader.drop()

__check_kmemleak()

# stop loggging
tf_cfg.cfg.log_listner.stop()
if len(result.failures) > 0 or len(result.unexpectedSuccesses) > 0 or len(result.errors) > 0:
    sys.exit(1)

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
