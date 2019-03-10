Custom HTTP response configuration can be extended to HTTPListener settings.
The HTTPListener supports the following new settings:

- Support static response. The `<static string>` is sent back as the HTTP
response as-is, without any further logic.
  HTTPListener uses the following pair:
```
Static_C2: static.evil.com, static2.evil.com
Static_Data: <Static string>
```


- Support static file response. The `<subpath within webroot>` specifies a path
within `webroot` directory. If the requested resource is found, the content of
the file is used as the HTTP resonse. Otherwise, we use the default Fakenet
page. HTTPListener uses the following pair:
```
StaticFile_C2: staticfile.evil.com, staticfile2.evil.com
StaticFile_Path: <subpath within webroot>
```


- Support dynamic content generation. The `provider_file_name.py` specifies a
python script within `webroot/providers`. The custom content provider only
needs to implement a HandleRequest function.
```
Custom_C2: custom.evil.com, custom2.evil.com
Custom_Provider: provider_file_name.py
```


Here is an example dynamic handler
```

'''
    Example Dynamic Request handler

    Method name must be 'HandleRequest'

    Parameter Request is a Type ThreadedHTTPRequestHandler

    This method must handle the request and write the response
'''
def HandleRequest(req, post_data=None):
    content = "Dynamic Response"
    content_type = "text/html"
    return content, content_type
```

