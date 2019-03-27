# Updating test framework


## Requirements

There are several types of tests (some of them are only planned and not
implemented yet):

- Message integrity. In these tests it's important to validate that the
message received from Tempesta is equal to the expected one. It applies to both
forwarded request and response. There should be an option to split messages sent
to Tempesta in every possible set of skbs.

- Invalid message processing. Tests to validate behaviour on invalid message
parsing/processing. Tempesta may send responses to sender or close the
connection.

- Scheduler tests. It's important which server connection was used to serve
the request.

- Cache tests. It's important whether a server connection was used to serve
the request or not.

- Request-response chain integrity. Need to validate that every client receives
its responses in the correct order.

- Fault injections. Based on other types of tests, but random errors to be
emulated using SystemTap or eBPF.

- Fussing. Generating random requests and responses, Tempesta must stay
operational and serve as many requests as possible.

- Workload testing. Generate pretty high request rate to confirm data safety
on highly concurrent code execution. The more CPUs is used for Tempesta -
the better. But CPU utilisation must be less than 80% to assure that no extreme
conditions happen.

- Stress testing. Testing under extreme conditions, when request rate is higher
than Tempasta can serve.

- Low level TCP testing. Some features can affect TCP behaviour, so need to
validate that the Tempesta conforms RFCs and doesn't break kernel behaviour.

- TLS testing. Having in-house TLS implementation gives great powers and great
responsibility. We must assure TLS support messages integrity, encryption
integrity. It differs from other tests, since it's important to work with raw
data lying under HTTP on client and server side.

- Tempesta-originated requests. Pretty specific tests, since Tempesta may
generate requests on its own, e.g. background cache revalidation, or health
monitor requests. It differs from other tests, since it's important to validate
support TCP messages.


There also some requirements on tests process:

- Full, reduced and extra-stability set of tests. Reduced for developers to
run before making pull requests. Full to run against pull requests.
Extra-stability for every night testing to assure stability under unpredictable
loads.

- Easy new test addition.

- Easy test case failure analysis.

- Generate a few tests based on singe test description. E.g. in fussing test
it's required to know, how the Tempesta would react on a message, and what
should be threated as error. The 'splitting on different skbs' is actually
fussing test feature, not functional. Usually it also make sense to generate
workload test based on functional profile.


## Problems of current implementation

The main problem is having two frameworks in the same time. Old, feature rich,
but too sophisticated, with requirement to understand 5-6 files to understand
what the test is actually does. And a new, more friendly, but not complete and
with lack of the most important features. Transition of an old one to a new
wasn't completed, and the development of both was rather unorganized, thus
new framework is becoming more and more complex and loses its advantages.

In both frameworks every test type is implemented as unique test, so it's
required to write message integrity, fussing, workload and many other test
cases for the same situation.

Heavy dependency between tests. When a new feature is added, it's added to the
test framework core and affects a lot of tests. Sometimes unpredictably and
badly.


## Proposed design

The proposed design improves the new test framework and intends to deliver it to
full-feature test tool.

The whole test case is described in single file, configuration of each entity
is listed as plain text template with some parameters. No procedure generated
configs like in old framework.

Most of the test cases should use following description:
```

class SomeTest(BaseTestClass):

    backends = [# For all tests except stress tests:
                {
                    'type'      : 'deproxy',
                    'id'        : 'id1',
                    'response'  : gen_response_func,
                },
                # OR:
                {
                    'type'      : 'wrk',
                    'id'        : 'id1',
                    'script'    : script_name,
                    # Other wrk-specific options.
                },
               ]
    clients  = [# For all tests except stress tests:
                {
                    'type'      : 'deproxy',
                    'id'        : 'id1',
                    'request'   : gen_request_func,
                    'response'  : response_cb,
                },
                # OR:
                {
                    'type'      : 'wrk'
                    'id'        : 'id1',
                    'script'    : script_name,
                    # Other wrk-specific options.
                },
               ]
    tempesta = {
                'config' : '...'
               }
    test_variations = ['functional', 'workload', 'fussing']

    def test(self):
        < ... test procedure steps ... >
        pass
```

It doesn't look very different from the current description of tests in the
new framework, but it completely different under the hood. So tests procedures
will significantly change.


### Client and Server Mocks

Each client and server are started in separate process. This is required since
python has no real multithreading capabilities (see Global Interpreterer Lock).
There already are multiple processes in the new framework, but final assertions
are done in main process making it difficult to check the used connections,
clients, servers and order.

With the proposed solution each mock client and server is to become separate
process with configured request-response sequence, all assertions is to be done
inside that mock processes. With this approach all tests will be closer to
mock client and server programming than programming of tests routines.


#### Mock Client

Separate process, started by the test framework. Has following arguments:

- Script. - filename with the request/response functions. The content of it
is described later.

- ID. - client id.

- Server address. - Address of Tempesta, IP and port.

- Interfaces. - interfaces the client sockets will be binded to
(using `SO_BINDTODEVICE` socket option).

- Concurrent connections. - Number of concurrent connections for each defined
interface.

- Debug file. - Filename to write debug information.

- Repeats. - Number of repeats of the request/response sequence before connection
is closed.

- RPS. - maximum rps.

- Split. - Boolean value, meaning that requests must be splited in multiple skbs.
Don't know how to implement it yet.

Client has two structures to contain required information: `client_data` for
global client data and `conn_data` for per connection data.

First, client waits for POSIX barrier until all other mock servers are ready.
Then for every connection it does the following algorithm:

1. Open a new connection and bind it to interface. Set `conn_data.request_id`
to `0`.

2. Call `gen_request_func()` from the script to generate the request.

3. Copy generated request to send buffer. Push request to `conn_data.request_queue`
and increment `conn_data.request_id`.

4. If not `conn_data.pipeline` go to step `5`, otherwise go to step `2`.

5. Send current buffer to Tempesta. Start `conn_data.req_timeout` timer.

6. Receive as many as possible. If `conn_data.req_timeout` is expired go to `err`

7. Try to parse response from the buffer. If full response is received go to `8`,
else go to `6`.

8. For complete response run `response_cb()` from the script. If error happen
go to `err`. Remove request from `conn_data.request_queue` If there are request
unreplied, go to `6`. Else stop  `conn_data.req_timeout` timer.

9. If there are unsent requests go to `2`.

10. Close connection. If `conn_data.repeats` go to `1`.

11. Exit.

`err.` Build error message, close connection and exit.


The algorithm talks about two functions: `gen_request_func()` and `response_cb()`.
Lets take a closer look.

`def gen_request_func(client_data, conn_data)`. Returns `request` if any or `None`.
Generic implementation should build the following request:
```
GET / HTTP/1.1
T-Client-Id: %client_data.client_id%
T-Conn-Id: %conn_data.conn_id%
T-Req-Id: %conn_data.request_id%

```
In the same time the function can modify following variables:
`conn_data.pipeline` - if set, the next request bust be pipelined. In defaults: `false`.
`conn_data.expect_close` - Connection should be closed by the peer after response to this request, `false` by defaults.
`conn_data.expect_reset` - Connection should be closed immediately, `false` by defaults.
`conn_data.close_timer` - Timer is set if connection is to be closed.

If a response is expected for the connection, `request.expected_response` must
be created.

Other variables may be added or set in `conn_data` or `client_data`.

`def response_cb(client_data, conn_data, response, closed)`. Return bolean success code.
The client receives some response:
```
HTTP/1.1 200 OK
T-Client-Id: %client_data.client_id%
T-Conn-Id: %conn_data.conn_id%
T-Req-Id: %conn_data.request_id%
< ... Standard Tempesta's headers ... >

```
All headers including `T-Client-Id`, `T-Conn-Id`, `T-Req-Id` must match
`conn_data.requests[0].expected_response`. Not all header may be matched
exactly, especially `Date`, `Age` and other time headers. If so, headers can't
have values smaller than expected. `T-Srv-Id` and `T-Srv-Conn-Id` headers may be
ignored in most tests.

Boolean `closed` argument is set to true if the connection was closed by the peer.
The function is also called if the connection was reset by peer, but no response
was received. In this case `response` is set to `None`.

If received response doesn't match expected one, then an error message is generated:
```
Error on request-response processing!
For request:
---
<Request>
---
Response was expected:
---
<Expected response>
---
But received response was:
---
<Received response>
---
```
Error should also be generated if the connection was closed unexpectedly or
connection wasn't closed as expected.


If debug is enabled, write to file `debug_filename_%connid%` any activity on the
connection with the timestamp: received bytes, sent bytes, and parsed messages.


#### Mock Server

Follows the same concept as mock client. Arguments:

- Script. - filename with the request/response functions. The content of it
is described later.

- ID. - server id.

- Interface:conns. - interfaces the client sockets will be listening and number
of Tempesta's connections for it.

- Split. - Boolean value, meaning that requests must be splited in multiple skbs.
Don't know how to implement it yet.

- Debug file. - Filename to write debug information.

Server is stopped by `TERM` signal from the framework.

Script contains queue of expected requests `server_data.requests[]`. If all
requests was received, but a new request is received, then client is working in
repeated mode, thus `conn_data.expected_request_num` must be reset to `0`.

`def gen_response_func(server_data, conn_data, request)` function is used to
give a response for the client. Returns `response` or `None`. The received
request is compared with `server_data.requests[T-Req-Id]`
but note, that `T-Client-Id`, `T-Conn-Id`, `T-Req-Id` values may be missed in the
expected request.

The generated response **must** contain headers copied from the request:
`T-Client-Id`, `T-Conn-Id`, `T-Req-Id`. `T-Srv-Id` and `T-Srv-Conn-Id` must
also be generated.

If the server need to close the connection in response to request, it sets
`conn_data.close` variable. The variable `conn_data.expect_close` can also be
set if generated response is invalid and Tempesta will reset the connection.


### Framework

The framework now is defined not as list of actions but as HTTP flows on client
and server. This allows to replace Tempesta by other HTTP ADC software and easily
compare behavior between them.

This also allows to create multiple tests from the same description:

- Message integrity, Invalid message processing, Cache tests: single client,
single client connection.

- Scheduler, Workload, Request-response chain integrity tests: multiple clients
from many source interfaces, multiple concurrent connections for each client.

- Fuzzing tests: Workload tests, but every generated messages are split into
different number of skbs.

When reduced number of tests is executed, only first group of tests is executed,
the full set is for first and second groups. All groups are executed in background
stability tests.

At the first sight Cache tests can't be executed multiple times.
But if `URI` and/or `Host:` mutated between different client connections and
repeats it becomes possible. Thus Cache Workload testing should be fine.

Fault injections tests are very similar to Message integrity tests, but a few
prior actions to inject errors are required before starting the client.


#### Prepare to start

Copy functions defined in `clients` and `server` array of test class to separate
file to start clients and servers as distinct processes. Probably other python
interpreters can be used for that. `Pypi` is extremely fast in comparing to
standard interpreter. This will allow pretty good RPS in work load tests.

The framework must create all required interfaces before start.

POSIX barrier is used to synchronize clients and servers. Clients shouldn't
start generating requests before all server connections are established.


## TBD

TLS tests - ?

Low level TCP testing - ?

Code coverage -?

There may many thing to be discussed, feel free to raise questions.
