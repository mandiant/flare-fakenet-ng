from datetime import datetime

def HandleRequest(req, method='GET', post_data=None):
    content = "Dynamic Response to %s method: %s" % (method, datetime.now())
    return content, "text/html" 
