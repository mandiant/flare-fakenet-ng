def HandleRequest(req, method, post_data=None):
    if method == 'GET':
        response = "I'm a little teapot"
        req.send_response(418)
        req.send_header('X-Teapot-Type', 'ShortAndStout')
        req.send_header('Content-Length', len(response))
        req.end_headers()

        req.wfile.write(response)

    elif method == 'POST':
        response = "Haste"
        req.send_response(200)
        req.send_header('Content-Length', len(response))
        req.end_headers()

        req.wfile.write(response)

    elif method == 'HEAD':
        req.send_response(200)
        req.end_headers()
