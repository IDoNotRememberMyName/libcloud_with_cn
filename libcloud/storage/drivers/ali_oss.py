# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import copy
import base64
import hmac

from hashlib import sha1
from email.utils import formatdate

from libcloud.utils.py3 import b

from libcloud.common.base import ConnectionUserAndKey

from libcloud.storage.drivers.s3 import BaseS3StorageDriver, S3Response, S3RawResponse


SIGNATURE_IDENTIFIER = 'OSS'

ALI_OSS_HOST = 'oss.aliyuncs.com'

class OSSConnection(ConnectionUserAndKey):
    """
    Represents a single connection to the Ali OSS Endpoint
    """

    host = ALI_OSS_HOST
    responseCls = S3Response
    rawResponseCls = S3RawResponse

    def add_default_headers(self, headers):
        date = formatdate(usegmt=True)
        headers['Date'] = date
        return headers

    def pre_connect_hook(self, params, headers):
        signature = self._get_oss_auth_param(
            method=self.method, headers=headers, params=params,
            expires=None, secret_key=self.key, path=self.action)
        headers['Authorization'] = '%s %s:%s' % (SIGNATURE_IDENTIFIER,
                self.user_id, signature)
        return params, headers

    def _get_oss_auth_param(self, method, headers, params, expires,
                            secret_key, path='/'):
        """
        Signature = URL-Encode( Base64( HMAC-SHA1( YourSecretAccessKeyID,
                                    UTF-8-Encoding-Of( StringToSign ) ) ) );

        StringToSign = HTTP-VERB + "\n" +
            Content-MD5 + "\n" +
            Content-Type + "\n" +
            Expires + "\n" +
            CanonicalizedOSSHeaders +
            CanonicalizedResource;
        """
        special_header_keys = ['content-md5', 'content-type', 'date']
        special_header_values = {'date': ''}
        ali_header_values = {}

        headers_copy = copy.deepcopy(headers)
        for key, value in list(headers_copy.items()):
            key_lower = key.lower()
            if key_lower in special_header_keys:
                special_header_values[key_lower] = value.strip()
            elif key_lower.startswith('x-oss-'):
                ali_header_values[key.lower()] = value.strip()

        if 'content-md5' not in special_header_values:
            special_header_values['content-md5'] = ''

        if 'content-type' not in special_header_values:
            special_header_values['content-type'] = ''

        if expires:
            special_header_values['date'] = str(expires)

        keys_sorted = list(special_header_values.keys())
        keys_sorted.sort()

        buf = [method]
        for key in keys_sorted:
            value = special_header_values[key]
            buf.append(value)
        string_to_sign = '\n'.join(buf)

        keys_sorted = list(ali_header_values.keys())
        keys_sorted.sort()

        ali_header_string = []
        for key in keys_sorted:
            value = ali_header_values[key]
            ali_header_string.append('%s:%s' % (key, value))
        ali_header_string = '\n'.join(ali_header_string)

        values_to_sign = []
        for value in [string_to_sign, ali_header_string, path]:
            if value:
                values_to_sign.append(value)

        string_to_sign = '\n'.join(values_to_sign)
        b64_hmac = base64.b64encode(
            hmac.new(b(secret_key), b(string_to_sign), digestmod=sha1).digest()
        )
        return b64_hmac.decode('utf-8')


class OSSStorageDriver(BaseS3StorageDriver):
    name = 'Ali Open Object Service'
    website = 'http://www.aliyun.com/products/oss/'
    connectionCls = OSSConnection
    hash_type = 'md5'
    supports_chunked_encoding = False
    supports_s3_multipart_upload = False
#   namespace must be overridden
    namespace = ''
    http_vendor_prefix = 'x-oss'
