# Functional Tests for TempestaFW

## Recommended configuration

Running tests during development process can cause crashes to TempestaFW.
Since TempestaFW is implemented as a set of kernel modules it is not convenient
to run testing framework on the same host. It is recommended to run testing
framework on a separated host.

Recommended test-beds:

- Local testing. All parts of the testing framework are running on the same
host. The simplest configuration to check that current revision of TempestaFW
passes all the functional tests. It is default configuration.
```
    ┌─────────────────────────────────────────────┐
    │ Testing Framework + TempestaFW + Web Server │
    └─────────────────────────────────────────────┘
```

- With isolated testing framework. This preset more helpful for development
process, since testing framework itself is isolated from possible kernel
crashes or hangs. This configuration is recommended for TempestaFW developers.
```
    ┌───────────────────┐
    │ Testing Framework ├────┐
    └──────┬────────────┘    │ Management over SSH
           │              ┌──┴──────────────────────┐
           │              │ TempestaFW + Web Server │
           │              └───────────────┬─────────┘
           └──────────────────────────────┘
          Separated network for test traffic
```

- Fully distributed. 3 different hosts with their own roles are used. This
configuration isolates traffic generated by benchmark utilities and traffic
generators in test network. Handy for stress and performance testing but require
a lot of resources.
```
    ┌───────────────────┐
    │ Testing Framework ├────┐
    └──────┬────────────┘    │ Management over SSH
           │                 ├────────────────────┐──────────────────┐
           │          ┌──────┴─────┐        ┌─────┴──────┐     ┌─────┴──────┐
           │          │ TempestaFW │        │ Web Server │     |   Client   |
           │          └──────┬─────┘        └─────┬──────┘     └─────┬──────┘
           └─────────────────┴────────────────────┴──────────────────┘
              Separated network for test traffic
```

There is three different models of tests: workload tests (deprecated),
pure functional tests (deprecated) and user configured tests.
Workload tests uses fully functional HTTP benchmark programs (ab, wrk) and
HTTP servers (Apache, nginx) to check TempestaFW behaviour. This type
of tests is used for schedulers, stress and performance testing.

Pure functional tests check internal logic. Here combined HTTP client-server
server is used. It sends HTTP messages to TempestaFW, analyses how they are
forwarded to server, and vice versa, which server connections are used.

User configured tests allow user to write their own tests with using high level
primitives, such as different types of clients and servers. Each test contains
2 parts: declaration of clients and servers and code of test, where this items
are started, stopped, requests performed, etc. Declarative description of tests
allows modify items without changing tests, because constructors are called by
framework instead of test. Both, workload and functional tests, can be rewritten
with user configured tests. Functional test should use deproxy client and
deproxy server, and workload tests should use wrk client and nginx server.

## Setup

To run requirements auto installation run setup.sh from `tempesta-test` directory

`./setup.sh`

## Requirements

- Host for testing framework: `python3`, `python3-paramiko`, `python3-scapy`,
`wrk`, `ab`, `nghttp2`, `configparser`, `pycryptodomex` and `tinyec`
  (the last three can be installed using `pip install pycryptodomex tinyec`), `tls-perf`
- All hosts except previous one: `sftp-server`
- Host for running TempestaFW: Linux kernel with Tempesta, TempestaFW sources,
  `systemtap`, `tcpdump`, `bc`
- Host for running server: `nginx`, web content directory accessible by nginx,
  nginx should not be running before the tests start

`wrk` is an HTTP benchmarking tool, available from [Github](https://github.com/wg/wrk).

`ab` is Apache benchmark tool, that can be found in `apache2-utils` package.

`h2spec` is HTTP/2 conformance test suite. Can't be installed from package
manager and must be retrieved from [GitHub](https://github.com/summerwind/h2spec/releases/latest).

`tls-perf` can be downloaded from our GitHub [repository](https://github.com/tempesta-tech/tls-perf).

Testing framework manages other hosts via SSH protocol, so the host running
testing framework must be able to be authenticated on other hosts by the key.
That can be done using `ssh-copy-id`. Root access is required on all hosts.

Requirements can be checked with `check_deps/check_dependencies.sh`. It should
be ran from `check_deps` directory.

## Run tests

### Configuration

Testing framework is configured via `tests_config.ini` file. Example
configuration is described in `tests_config.ini.sample` file.
You can also create default tests configuration by calling:

```sh
$ ./run_tests.py -d
```

There is 4 sections in configuration: `General`, `Client`, `Tempesta`, `Server`.

#### General Section

`General` section describes the options related to testing framework itself.

`ip` — IPv4/IPv6 address of the host running the testing framework, as reachable
from the host running TempestaFW.

`verbose`: verbose level of output:
- `0` — quiet mode, result of each test is shown by symbols. `.` — passed, `F` -
failed, `u` — unexpected success, `x` — expected failure. `s` — skipped;
- `1` — Show test names and doc strings;
- `2` — Show tests names and performance counters;
- `3` — Full debug output.

`duration` option controls duration in seconds of each workload test. Use small
values to obtain results quickly add large for more heavy stress tests. Default
is `10` seconds.

`log_file` option specifies a file to tee (duplicate) tests' stderr to.

`workdir` - path to temporary files, e.g. TLS certificates generated by
the framework.

This group of options can be overridden by command line options, for more
information run tests with `-h` key.
```sh
$ ./run_tests.py -h
```

#### Client Section

Clients are always ran locally (on the same host where the testing framework
runs). In certain tests, backend servers are also ran locally (disregarding
[server configuration](#server-section)).

`ip` — IPv4/IPv6 address of this host in the test network, as reachable from
the host running TempestaFW.

`workdir` — absolute path to a R/W directory on the host to place temporary
files in.

`ab`, `wrk` — paths to the corresponding binaries, either absolute paths or
names available in PATH.

#### Tempesta Section

`ip` — IPv4/IPv6 address of the TempestaFW host in test network, as reachable
from the client and server hosts.

`hostname`, `port`, `user` — address and credentials used to reach the host via
SSH. If hostname is `localhost`, TempestaFW will be ran locally.

`workdir` — absolute path to the TempestaFW source tree.

`config` — workdir-relative or absolute path to the temporary TempestaFW config
that will be created during testing.


#### Server Section

`ip` — IPv4/IPv6 address of the backend server host in test network, as
reachable from the host running TempestaFW.

`workdir` — absolute path to a R/W directory on the host to place temporary
files in.

`nginx` — path to the corresponding binary, either absolute path or a name
available in PATH.

`resources` — absolute path to a sample web site root. Must be reachable by
nginx.

### Run tests

To run all the tests simply run:
```sh
$ ./run_tests.py
```

To run individual tests, name them in the arguments to the `run_tests.py` script
in dot-separated format (as if you were importing them as python modules,
although it is also possible to run specific testcases or even methods inside a
testcase):
```sh
$ ./run_tests.py cache.test_cache
$ ./run_tests.py cache.test_cache.TestCacheDisabled.test_cache_fullfill_all
```

To ignore specific tests, specify them in the arguments prefixed with `-`
(you may need to use `--` to avoid treating that as a flag):
```sh
$ ./run_tests.py cache -cache.test_purge # run cache.*, except cache.test_purge.*
$ ./run_tests.py -- -cache # run everything, except cache.*
```

If the testsuite was interrupted or aborted, next run will continue from the
interruption point. The resumption information is stored in the
`tests_resume.txt` file in the current working directory. It is also possible
to resume the testsuite from a specific test:
```sh
$ ./run_tests.py --resume flacky_net
$ ./run_tests.py --resume-after cache.test_purge
```

In all cases, prefix specifications are allowed, i. e. `cache.test_cache` will
match all tests in `cache/test_cache.py`, but `test_cache` will not match
anything. When resuming, execution will continue from (after) the first test
that matches the specified string.

## Adding new tests

**WARNING**: there are 2 testing frameworks in directories `testers` and `framework`.
Please use only `framework` for the new tests. `testers` is deprecated and must be
removed in https://github.com/tempesta-tech/tempesta-test/issues/56 .

Adding new tests is easy. First, create new Python file in the new Python module
(directory) or existing one.
Name of the file must be started with `test_`
```sh
$ mkdir my_test
$ touch my_test/test_some_feature.py
$ echo "__all__ = [ 'test_some_feature' ]" >> my_test/__init.py__
```

Import `framework.tester`: `from framework import tester`,
and derive you test class from `tester.TempestaTest`

`class Test(tester.TempestaTest)`

This class should have lists with backend
and client configuration.

`backends = [...]`
`clients = [...]`

Each config is a structure, containing item id, type, and
other options, depending on item type.

Now such backends are supported:
1) type == nginx
    - status_uri: uri where nginx status is located
    - config: nginx config

2) type == deproxy
    - port: listen this port
    - response: type of response. Now only 'static' is supported
      - response == static:
         - response_content: always response this content,
         - keep_original_data: optional: if set to True,
                the original request will be kept in Request.original_data field
                as it has arrived by the wire,
                otherwise (say, the parameter is not defined at all)
                Request.original_data will be left blank
         - segment_size: optional: TCP segment size for heavy chunked testing, bytes, 0 for disable
         - segment_gap: optional: inter-segment gap for heavy chunked testing, ms, 0 for disable
              - you usualy do not need it; update timeouts if you use it

and such clients:
1) type == wrk
    - addr: 'ip:port'

2) type == deproxy
    - addr: ip addr of server to connect
    - port: port
    - keep_original_data: optional: if set to True,
           the original response will be kept in Response.original_data field
           as it has arrived by the wire,
           otherwise (say, the parameter is not defined at all)
           Response.original_data will be left blank
    - segment_size: optional: TCP segment size for heavy chunked testing, bytes, 0 for disable
    - segment_gap: optional: inter-segment gap for heavy chunked testing, ms, 0 for disable
       - you usualy do not need it; update timeouts if you use it

All options are mandatory, unless explicitly stated otherwise.

nginx config, deproxy response, addr and port can use templates
in format `${part_variable}` where `part` is one of 'server',
'tempesta', 'client' or 'backend'

Warning: deproxy backend now is running on the Framework host, so
framework ip should be specified in tempesta config.

Example tests can be found in `selftests/test_framework.py`

Tests can be skipped or marked as expected to fail.
More info at [Python documentation](https://docs.python.org/3/library/unittest.html).

### Testing with chunked messages

Some tests require division of request or response into small TCP segments ("chunks").
This division is controlled by segment_size parameter of the client or the backend
(see above). Usualy better to set this parameter programmaticaly rather than in client
or backend configuration.

An example to create tests which divide requests or responsies into chunks and
iterate over various chunk sizes is here: `malformed/test_chunking_example.py`.

## Internal structure and motivation of user configured tests

User configured tests have very flexible structure. They allow arbitrary
clients and server start, stop, making requests. This leads to several
points in internal structure.

### Using separate thread for polling cycle

Now, deproxy client and deproxy server, all of them use the single polling
cycle, as it was in functional tests. But we have differencies.

We have 3 cases of using deproxy clients and server:

1) both deproxy client and server are used

2) only deproxy client is used

3) only deproxy server is used

First case corresponds to functional tests. The second and third have no
corresponding case in old testing framework.

And case 3 leads to instant running of polling cycle in separate thread.
Indeed, let's consider case of wrk client and deproxy server without instant
running of this cycle. We start deproxy server, then we start wrk client
and after this we start polling cycle. The time before starting cycle,
wrk will get an errors. Ok, let's start polling cycle before wrk. But now it's
impossible to start wrk, because we are in polling cycle. This problem appeares,
because with running polling cycle in the same thread, as the main procedure,
deproxy server can receive requests only after polling cycle starts.

The solution is to make possible handling requests exactly when server starts.
In this case test procedure becames simple and straightforward: start deproxy
server, the start wrk. And this became possible with polling cycle, running in
separate thread.

But using separate thread leads to requirements of using locks. It's appeared
that creating new connection while polling function is running in it's thread,
can lead to error. So we should be sure, that it won't happen. That's why locks
are used.

          Main thread                  Thread with poll loop

            |                                   |
            | ------------------------------- Lock()
            |                                   |
            |                                 Poll()
            |                                   |
            | ------------------------------ Unlock()
            |                                   |
            .                                   .
            .                                   .
            .                                   .
            |                                   |
            |                                 Lock()
    client or server                            |
         start()                               Poll()
            \                                   |
             \                               Unlock()
            Lock() ---------------------------- |
              |                                 |
        create socket                           |
              |                                 |
        connect or listen                       |
              |                                 |
          Unlock() ---------------------------- |
              |                               Lock()
            return                              |
             /                                Poll()
            |                                   |
            |                                Unlock()
            |                                   |
            .                                   .
            .                                   .
            .                                   .

### Classes used

Code of configurable tests located in `framework/` directory. It contains
basic class for configurable test and classes for items. Also it contains
class for deproxy management and polling cycle.

#### TempestaTest

Basic class for user configured tests. Contains parsing of used items
declaration (clients, backends, tempesta), startup and teardown functions.
User configured tests should inherit it.

Also there are cases when you most likely would want to create a basic abstract
class for a group of tests and utilize Python's inheritance mechanism. In order
to do that, just pass an argument `base` upon class creation, e.g.:

```python
class HttpTablesTestBase(tester.TempestaTest, base=True):
    ...

```
and tests won't be called for that particular class.

Default `base` value is `False`.

Note that if you override `setUp` method, please, don't forget to put
```python
...
super().setUp()
...
```
in there, otherwise this feature won't work properly.

#### DeproxyManager

This class is a stateful wrap for the `run_deproxy_server()` function.
This function contains a polling cycle. DeproxyManager creates new thread for
this function, and stops it, when received `stop()`. DeproxyManager starts
in test `setUp()` and stops in `tearDown()`. So, polling cycle run all the
test time.

#### FreePortsChecker

When we start backend, it can appear, that specified port is already used
by smth. So server startup will fail. We can make all servers to write about
this, but it simpler to check free ports before start server.

#### Classes for servers and clients

deproxyclient, deproxyserver, nginx, wrk - this classes used for creating
and handling corresponding types of items.


## Development

In the project we use [![wemake-python-styleguide](https://img.shields.io/badge/style-wemake-000000.svg)](https://github.com/wemake-services/wemake-python-styleguide)
[![pre-commit](https://img.shields.io/badge/pre--commit-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)

Install development dependencies: `pip3 install -r requirements-dev.txt`

Copy `pre-commit.sample` to .git/hooks directory, rename to `pre-commit` and make file executable:
```sh
$ cp pre-commit.sample pre-commit 
$ mv pre-commit .git/hooks 
$ chmod +x .git/hooks/pre-commit
```

Configuration file `tox.ini`

Run linter `flake8 <target>`:

  where `tagret` is optional parameter, it defines target file to be checked,
  if omitted, checks is going to be processed on all files in running directory.

Use `git commit -v -all` to check all changed python files.

## Resources

There are not so much good references about best practices in development of
testing framework.

* [Why Good Developers Write Bad Tests](https://www.youtube.com/watch?v=oO-FMAdjY68)
