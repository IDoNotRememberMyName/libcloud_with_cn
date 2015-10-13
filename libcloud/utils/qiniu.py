from base64 import urlsafe_b64encode,urlsafe_b64decode
from .qiniu_compat import b, s

def urlsafe_base64_encode(data):
    ret = urlsafe_b64encode(b(data))
    return s(ret)
