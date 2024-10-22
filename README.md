# Functional Tests for TempestaFW

## Recommended configuration

Running tests during development process can cause crashes to TempestaFW.
Since TempestaFW is implemented as a set of kernel modules it is not convenient
to run testing framework on the same host. It is recommended to run TempestaFW 
on a separated host.

Recommended test-beds:

- Local testing. All parts of the testing framework are running on the same
host. The simplest configuration to check that current revision of TempestaFW
passes all the functional tests. It is default configuration.
```
    ┌──────────────────────────────────────────────────────┐
    │ Testing Framework + Client + TempestaFW + Web Server │
    └──────────────────────────────────────────────────────┘
```

- With isolated testing framework. 2 different hosts with their own roles are used.
This configuration generates real network traffic. Handy for stress and performance 
testing but require a lot of resources.
This configuration is recommended for TempestaFW developers.
```
    ┌───────────────────┐
    │    TempestaFW     ├────┐
    └──────┬────────────┘    │ Management over SSH
           │              ┌──┴──────────────────────────────────────┐
           │              │ Testing Framework + Client + Web Server │
           │              └───────────────┬─────────────────────────┘
           └──────────────────────────────┘
          Separated network for test traffic
```

## Setup

To run requirements auto installation run setup.sh from `tempesta-test` directory 
as root:

`./setup.sh`

## Requirements

- Python version till 3.11 is supported, version **3.12 is NOT supported**
(we use [asyncore](https://docs.python.org/3.11/library/asyncore.html) that was removed in 3.12)

- Host for testing framework: `python3`, `wrk`, `ab`, `nghttp2`, `h2spec`, 
`curl`, `h2load`, `tls-perf`, `netstat`, `lxc`, `nginx`, `docker.io`, web content 
directory accessible by nginx, nginx should not be running before the tests start.
See Python libraries in `requirements.txt`
- All hosts except previous one: `sftp-server`
- Host for running TempestaFW: Linux kernel with Tempesta, TempestaFW sources,
  `systemtap`, `tcpdump`, `bc`

`wrk` is an HTTP benchmarking tool, available from [Github](https://github.com/wg/wrk).

`ab` is Apache benchmark tool, that can be found in `apache2-utils` package.

`h2spec` is HTTP/2 conformance test suite. Can't be installed from package
manager and must be [compiled from sources](https://github.com/tempesta-tech/h2spec#build).

`tls-perf` can be downloaded from our GitHub [repository](https://github.com/tempesta-tech/tls-perf).

Linux kernel for TempestaFW recommended to install using [kernel_installer.py](https://github.com/tempesta-tech/tempesta-ci/tree/master/scripts)

Testing framework manages other hosts via SSH protocol, so the host running
testing framework must be able to be authenticated on other hosts by the key.
That can be done using `ssh-copy-id`. Root access is required on all hosts.

Requirements can be checked with `check_deps/check_dependencies.sh`. It should
be ran from `check_deps` directory.

## Run tests

### Configuration

Testing framework is configured via `tests_config.ini` file. Example
configuration is described in `tests_config.ini.sample` file.
You can also create default tests configuration 
(see `TestFrameworkCfg.defaults` method from `helpers/tf_cfg.py`) by calling:

```sh
./run_tests.py -d
```

There is 4 sections in configuration: `General`, `Client`, `Tempesta`, `Server`.

### Run tests

To run all the tests simply run:
```sh
./run_tests.py
```

To run individual tests, name them in the arguments to the `run_tests.py` script
in dot-separated format (as if you were importing them as python modules,
although it is also possible to run specific testcases or even methods inside a
testcase):
```sh
./run_tests.py cache.test_cache
./run_tests.py cache.test_cache.TestCacheDisabled.test_cache_fullfill_all
```

Or you can run all tests from a file:
```sh
./run_tests.py selftests/test_deproxy.py 
```

Or you can run individual tests (or test class) using `-H` options:

```sh
./run_tests.py -H selftests/test_deproxy.py 
[?] Select test class: DeproxyTestH2
   DeproxyChunkedTest
   DeproxyClientTest
   DeproxyDummyTest
   DeproxyTest
   DeproxyTestFailOver
 > DeproxyTestH2
   ProtocolError

[?] Select test method: ALL
 > ALL
   test_bodyless
   test_bodyless_multiplexed
   test_disable_huffman_encoding
   test_get_4xx_response
   test_make_request
   test_no_parsing_make_request
   test_parsing_make_request
   test_with_body
```

To ignore specific tests, specify them in the arguments prefixed with `-`
(you may need to use `--` to avoid treating that as a flag):
```sh
./run_tests.py cache -cache.test_purge # run cache.*, except cache.test_purge.*
./run_tests.py -- -cache # run everything, except cache.*
```

If the testsuite was interrupted or aborted, next run will continue from the
interruption point. The resumption information is stored in the
`tests_resume.txt` file in the current working directory. It is also possible
to resume the testsuite from a specific test:
```sh
./run_tests.py --resume flacky_net
./run_tests.py --resume-after cache.test_purge
```

In all cases, prefix specifications are allowed, i. e. `cache.test_cache` will
match all tests in `cache/test_cache.py`, but `test_cache` will not match
anything. When resuming, execution will continue from (after) the first test
that matches the specified string.

## Adding new tests

**WARNING**: there are 2 testing frameworks in directories `testers` and `framework`.
Please use only `framework.testet.TempestaTest` for the new tests. 
`testers.functional.FunctionalTest` and `testers.stress.StressTest` are deprecated and 
must be removed in https://github.com/tempesta-tech/tempesta-test/issues/56 .

### Requirements to adding new tests:
1. Name of the test directory must be started with `t_` prefix;
2. Name of the file must be started with `test_` prefix;

```sh
mkdir t_new_directory
touch t_new_directory/test_some_feature.py
echo "__all__ = [ 'test_some_feature' ]" >> my_test/__init.py__
```

3. Name of the test class must be started with `Test` prefix;

```python3
from test_suite import tester

class TestCases(tester.TempestaTest):
    ...
```

4. Test class must contain TempestaFW, backend and client configuration. Each config is 
a structure, containing item id, type, and other options, depending on item type. 
TempestaFW config, deproxy response, addr and port can use templates in format 
`${part_variable}` where `part` is one of 'server', 'tempesta', 'client' or 'backend'. 
For example:

```python3
backends = [
    {
        "id": "deproxy",
        "type": "deproxy",
        "port": "8000",
        "response": "static",
    },
    {
        "id": "nginx",
        "type": "nginx",
        "status_uri": "http://${server_ip}:8000/nginx_status",
        "config": "nginx config as string",
    }
]

clients = [
    {
        "id": "deproxy",
        "type": "deproxy_h2",  # "deproxy" for HTTP/1
        "addr": "${tempesta_ip}",
        "port": "443",
        "ssl": True,
    },
    {"id": "wrk", "type": "wrk", "addr": "${server_ip}:8000"},
    {
        "id": "external",
        "type": "external",
        "binary": "curl",
        "cmd_args": "-Ikf http://${tempesta_ip}:80/",
    },
    {"id": "curl", "type": "curl", "h2": True},
]

tempesta = {
    "config": """
        listen 80;
        server ${server_ip}:8000;
    """
}
```

5. We use decorators to parameterize the tests (please don't use inheritance):

```python3
from test_suite import tester
from test_suite import marks


@marks.parameterize_class(
  [
    {"name": "Http", "clients": ["http_config"]},
    {"name": "H2", "clients": ["h2_config"]},
  ]
)
class TestExample(tester.TempestaTest):
  @marks.Parameterize.expand(
    [
      marks.Param(name='1', key_1="value_1"),
      marks.Param(name='2', key_1="value_2"),
    ]
  )
  def test_request(self, name, key_1):
    ...

# we will get 4 tests:
# TestExampleHttp.test_request_1
# TestExampleHttp.test_request_2
# TestExampleH2.test_request_1
# TestExampleH2.test_request_2
```

Example tests can be found in `selftests/test_framework.py`

Tests can be skipped or marked as expected to fail.
More info at [Python documentation](https://docs.python.org/3/library/unittest.html).

### Testing with chunked messages

WARNING: only for deproxy client and server, and it only works on local configuration.

Some tests require division of request or response into small TCP segments ("chunks").
This division is controlled by `segment_size` parameter of the client or the backend
(see above). Usualy better to set this parameter programmaticaly rather than in client
or backend configuration. You can run any test with TCP segmentation using `-T` option:

```shell
./run_tests.py -T 10 selftests/test_deproxy.py 
```

## Internal structure and motivation of user configured tests

User configured tests have very flexible structure. They allow arbitrary
clients and server start, stop, making requests. This leads to several
points in internal structure.

### Using separate thread for polling cycle

Now, deproxy client and deproxy server, all of them use the single polling
cycle. We have 3 cases of using deproxy clients and server:

1) both deproxy client and server are used

2) only deproxy client is used

3) only deproxy server is used

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
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Imports: isort](https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat&labelColor=ef8336)](https://pycqa.github.io/isort/)

Install dependencies: `pip3 install -r requirements.txt`

There may be a possible problem related to `scapy`, `paramiko`, and `cryptography`. 
`paramiko` will install `cryptography==43.0.3`, but `scapy~=2.5.0rc2` cannot work
with such a version of `cryptography` producing `ModuleNotFoundError: No module named 'cryptography.hazmat.backends.openssl.ec'`
We added `cryptography==38.0.2` on the top of `requirements.txt` to install it first.

If you still encounter a mentioned exception, try to run the next commands: 
```bash
pip uninstall -y cryptography
pip install cryptography==38.0.2
```


Run `pre-commit install` to set up the git hook script.

Run `pre-commit autoupdate` for update to the latest repos' versions (optional).

Configuration files: wemake - `tox.ini`, black and isort - `pyproject.toml`, pre-commit - `.pre-commit-config.yaml`.

Run formatters `isort <source_file_or_directory>` and `black <source_file_or_directory>`

Run linter `flake8 <target>`:

  where `tagret` is optional parameter, it defines target file to be checked,
  if omitted, checks is going to be processed on all files in running directory.

Use `git commit -v --all` to format all changed python files or just use `git commit -m <msg>`.

## Resources

There are not so much good references about best practices in development of
testing framework.

* [Why Good Developers Write Bad Tests](https://www.youtube.com/watch?v=hM_ex4-xu4E)
