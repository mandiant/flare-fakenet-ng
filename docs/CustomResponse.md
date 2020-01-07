# Custom Response Configuration

The Custom Response feature enables customization of responses either
statically or as user-supplied Python script code.

This enables convenient C2 server development for malware analysis purposes
beyond what can be achieved by emplacing files in the service root (e.g. under
`defaultFiles/` in the default configuration) and without having to modify
default listener source code that is unavailable in the binary release of
FakeNet-NG.

Currently the `TCPListener` and `HTTPListener` both accept a setting named
`Custom` that allows the user to specify Custom Response behavior.

The `Custom` setting indicates the name of a custom response configuration file
in the same location and format as the active FakeNet-NG configuration file.
Example custom response configuration files are supplied under
`fakenet/configs/`.

Each section of the custom response configuration file must specify which
listener(s) to configure. Valid listener configuration specifications are:
* `ListenerType`: must be `HTTP` for any `HTTPListener` or `TCP` for any
  `RawTCPListener`.
* `ListenerName`: must be the name of the listener to be configured.

If both the `ListenerType` and `ListenerName` listener specifications are
present in a single section, they will be evaluated disjunctively (logical or).

Further details are documented below for HTTP and TCP Listeners.

## HTTP Listener Custom Responses

Aside from which listener instances to configure, the HTTP custom response
configuration section must specify:
* Which requests to match
* What response to return.

Valid HTTP request matching specifications are:
* `HttpHosts`: a comma-separated list of hostnames that will match against
  host headers.
* `HttpURIs`: a comma-separated list of URIs that will match against request
  URIs.

If the `HttpHosts` specification includes a colon-delimited port number, it
will only match if the host header includes the same colon-delimited port
number.

If both the `HttpHosts` and `HttpURIs` matching specifications are present in
a single section, they will be evaluated conjunctively (logical and).

Valid HTTP custom response specifications are:
* `HttpRawFile`: Returns the raw contents of the specified file located under
  the web root, with the exception of date replacement.
* `HttpStaticString`: Wraps the specified string with server headers and a 200
  OK response code, replacing `\r\n` tokens with actual CRLFs and performing
  date replacement as necessary.
	* `ContentType`: Optionally, you accompany the `HttpStaticString` setting
	  with an  HTTP `Content-Type` header value to send. It is an error to
	  specify this setting with any other kind of response specification.
* `HttpDynamic`: Loads the specified Python file located under the web root
  and invokes its `HandleRequest` function as described below.

Date replacement applies to both `HttpRawFile` and `HttpStaticString`, and
replaces any occurrences of `<RAW-DATE>` in the specified text with a
server-formatted date.

### Implementing the HttpDynamic Response Handler

The `HandleRequest` method must conform to the following prototype:

```
def HandleRequest(req, method, post_data=None):
	"""Handle an HTTP request.

	Parameters
	----------
	req : BaseHTTPServer.BaseHTTPRequestHandler
		The BaseHTTPRequestHandler that recevied the request
	method: str
		The HTTP method, either 'HEAD', 'GET', 'POST' as of this writing
	post_data: str
		The HTTP post data received by calling `rfile.read()` against the
		BaseHTTPRequestHandler that received the request.
	"""
	pass
```

An example HTTP dynamic response handler is supplied in
`defaultFiles/CustomProviderExample.py`

## TCP Listener Custom Responses

TCP Listener Custom Responses implement no request filtering and implement only
response specifications.

Valid TCP custom response specifications are:
* `TcpRawFile`: Returns the raw contents of the specified file located under
  the configuration root, with the exception of date replacement.
* `TcpStaticString`: Sends the specified string as-is
* `TcpStaticBase64`: Base64 decodes the specified Base64-encoded data and sends
  the result as-is
* `TcpDynamic`: Loads the specified Python file located under the web root
  and invokes its `HandleTcp` function as described below.

### Implementing the TcpDynamic Response Handler

The `HandleTcp` method must conform to the following prototype:

```
def HandleTcp(req):
	"""Handle a TCP buffer.

	Parameters
	----------
	req : SocketServer.BaseRequestHandler
		The BaseRequestHandler that recevied the connection

	Available attributes and methods:
	req.request:
		req.request.settimeout()
		req.request.recv(n)
		req.request.sendall(s)
	req.server.logger
	"""
	pass

```
