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

from libcloud.utils.py3 import httplib
from libcloud.utils.py3 import b

from libcloud.common.base import ConnectionUserAndKey
from libcloud.common.types import InvalidCredsError
from libcloud.storage.base import Object, Container
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

    def get_container(self, container_name):
        try:
            response = self.connection.request('/%s?location' % container_name)
            if response.status == httplib.NOT_FOUND:
                raise ContainerDoesNotExistError(value=None, driver=self,
                                                 container_name=container_name)
        except InvalidCredsError:
            # This just means the user doesn't have IAM permissions to do a
            # GET request but other requests might work.
            pass
        return Container(name=container_name, extra=None, driver=self)


    def _put_object(self, container, object_name, upload_func,
                    upload_func_kwargs, method='PUT', query_args=None,
                    extra=None, file_path=None, iterator=None,
                    verify_hash=True, storage_class=None):
        headers = {}
        extra = extra or {}
        storage_class = storage_class or 'standard'
        if storage_class not in ['standard', 'reduced_redundancy']:
            raise ValueError(
                'Invalid storage class value: %s' % (storage_class))

        key = self.http_vendor_prefix + '-storage-class'
        headers[key] = storage_class.upper()

        content_type = extra.get('content_type', None)
        meta_data = extra.get('meta_data', None)
        acl = extra.get('acl', None)

        if meta_data:
            for key, value in list(meta_data.items()):
                key = self.http_vendor_prefix + '-meta-%s' % (key)
                headers[key] = value

        if acl:
            headers[self.http_vendor_prefix + '-acl'] = acl

        request_path = self._get_object_path(container, object_name)

        if query_args:
            request_path = '?'.join((request_path, query_args))

        # TODO: Let the underlying exceptions bubble up and capture the SIGPIPE
        # here.
        # SIGPIPE is thrown if the provided container does not exist or the
        # user does not have correct permission
        result_dict = self._upload_object(
            object_name=object_name, content_type=content_type,
            upload_func=upload_func, upload_func_kwargs=upload_func_kwargs,
            request_path=request_path, request_method=method,
            headers=headers, file_path=file_path, iterator=iterator)

        response = result_dict['response']
        bytes_transferred = result_dict['bytes_transferred']
        headers = response.headers
        response = response.response
        server_hash = headers['etag'].replace('"', '').lower()

        if (verify_hash and result_dict['data_hash'] != server_hash):
            raise ObjectHashMismatchError(
                value='MD5 hash checksum does not match',
                object_name=object_name, driver=self)
        elif response.status == httplib.OK:
            obj = Object(
                name=object_name, size=bytes_transferred, hash=server_hash,
                extra={'acl': acl}, meta_data=meta_data, container=container,
                driver=self)

            return obj
        else:
            raise LibcloudError(
                'Unexpected status code, status_code=%s' % (response.status),
                driver=self)
