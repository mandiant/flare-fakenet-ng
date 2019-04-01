# HTTP Listener Custom Responses

The `HTTPListener` can accept a setting named `Custom` that enables
customizable responses beyond what can be achieved by emplacing files in the
web root (e.g. under `defaultFiles/`).

The `HTTPListener` `Custom` setting indicates the name of an HTTP custom
response configuration file in the same location and format as the active
FakeNet-NG configuration file. An example HTTP custom response configuration
file is supplied in `fakenet/configs/sample_http_custom.ini`.

The sections of the HTTP custom response configuration file can define a series
of named rules regarding how to match requests and what to return.

Valid matching specifications are:
* `MatchHosts`: a comma-separated list of hostnames that will match against
  host headers.
* `MatchURIs`: a comma-separated list of URIs that will match against request
  URIs.

If both matching specifications are present in a single section, they will be
evaluated conjunctively (logical and).

Valid response specifications are:
* `RawFile`: Returns the raw contents of the specified file located under
  the web root, with the exception of date replacement.
* `StaticString`: Wraps the specified string with server headers and a 200 OK
  response code, replacing `\r\n` tokens with actual CRLFs and performing date
  replacement as necessary.
    * `ContentType`: Optionally, you accompany the `StaticString` setting with
      an  HTTP `Content-Type` header value to send. It is an error to specify
      this setting with any other kind of response specification.
* `Dynamic`: Loads the specified Python file located under the web root
  and invokes its `HandleRequest` function as described below.

Date replacement applies to both `RawFile` and `StaticString`, and replaces any
occurrences of `<RAW-DATE>` with a server-formatted date.

## Implementing a Dynamic Response Handler

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

An example dynamic response handler is supplied in
`defaultFiles/HTTPCustomProviderExample.py`
