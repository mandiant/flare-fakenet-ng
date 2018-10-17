I've hacked in support for custom responses.

I've added a new command line option to fakenet: '-r'. This option allows you to specify a json configuration which defines different custom response types. The current code only works with HTTP/HTTPS, however, I can think of situations where having an easy custom response handler for other protocols would be helpful, such as DNS.

Here is an example json configuration.

```
[
    {
        "some.random.c2.com":
        {
            "dynamic": "C2_Impl.py"
        }
    },
    {
        "api.ipify.org":
        {
            "static": "1.2.3.4"
        }
    },
    {
        "static.example.com":
        {
            "static-file": "static_file.bin",
            "content-type": "text/plain"
        }
    }
]

```

The config consists of an array of hosts. For each how you must specify: static, static-file, or dynamic. When an HTTP request is received by fakenet it first checks this array, comparing the HTTP Host header with the items in the array. If item in the array was set as `static` fakenet returns the static string defined in the configuration. If the array item was set as `static-file`, fakenet returns the contents of the file (same directory as config), and uses the specified `content-type` from the configuration. Additionally, we can now handle a custom `dynamic` response based on a host. The dynamic configuration takes a ptython filename which is responsible for handling the request and response data.

If any error occurs while processing any of the above, we default to returning the standard default file.

Here is an example dynamic handler
```

'''
    Example Dynamic Request handler

    Method name must be 'HandleRequest'

    Parameter Request is a Type ThreadedHTTPRequestHandler

    This method must handle the request and write the response
'''
def HandleRequest(req, post_data = None):
    content = "Dynamic Response"

 
    req.send_response(200)
    req.send_header("Content-Type", 'text/html')
    req.send_header("Content-Length", len(content))
    req.end_headers()
    req.wfile.write(content)


```

