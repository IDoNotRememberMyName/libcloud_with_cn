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

from hashlib import sha1
import hmac
import base64
import os
import ssl
import copy
import re
from time import time


from libcloud.utils.py3 import httplib
from libcloud.utils.py3 import urlencode

try:
    import simplejson as json
except ImportError:
    import json

from libcloud.utils.py3 import PY3
from libcloud.utils.py3 import b
from libcloud.utils.py3 import urlquote

if PY3:
    from io import FileIO as file

from libcloud.utils.files import read_in_chunks, guess_file_mime_type
from libcloud.common.types import MalformedResponseError, LibcloudError
from libcloud.common.base import JsonResponse, RawResponse, ConnectionUserAndKey

from libcloud.storage.base import Object, Container, StorageDriver
from libcloud.storage.base import DEFAULT_CONTENT_TYPE
from libcloud.storage.types import ContainerAlreadyExistsError
from libcloud.storage.types import ContainerDoesNotExistError
from libcloud.storage.types import ContainerIsNotEmptyError
from libcloud.storage.types import ObjectDoesNotExistError
from libcloud.storage.types import ObjectHashMismatchError
from libcloud.storage.types import InvalidContainerNameError
from libcloud.storage.types import InvalidObjectNameError

from libcloud.storage.drivers.s3 import BaseS3StorageDriver
from libcloud.storage.drivers.cloudfiles import CloudFilesStorageDriver

BCS_HOST = 'bcs.duapp.com'
EXPIRATION_SECOND = 15 * 60

class BCSResponse(JsonResponse):
    valid_response_codes = [httplib.NOT_FOUND, httplib.FORBIDDEN]

    def success(self):
        i = int(self.status)
        return i == 200 or i in self.valid_response_codes


class BCSRawResponse(BCSResponse, RawResponse):
    pass


class BCSConnection(ConnectionUserAndKey):
    host = BCS_HOST
    expire_time_flag = False
    ip = None
    size = None
    responseCls = BCSResponse
    rawresponseCls = BCSRawResponse

    def add_default_params(self, params):
        if self.expire_time_flag:
            params['time'] = str(int(time.time()) + EXPIRATION_SECONDS)
        if self.ip:
            params['ip'] = self.ip
        if self.size:
            params['size'] = self.size
        return params

    def pre_connect_hook(self, params, headers):
        params['sign'] = self._calculate_signature(
                method=self.method, secret_key=self.key,
                path=self.action, time=params.get('time'),
                ip=params.get('ip'), size=params.get('size'))
        return params, headers

    def _calculate_signature(self, method, secret_key, path='/',
                             time=None, ip=None, size=None):
        """
        """
        flag = 'MBO'
        content = ''
        content += 'Method=%s\n' % method

        name_list = path.split('/')
        while '' in name_list:
            name_list.remove('')
        #print name_list,path

        if 0 == len(name_list):
            bucket_name = ''
            object_name = '/'
        elif 1 == len(name_list):
            bucket_name = name_list[0]
            object_name = '/'
        elif 2 == len(name_list):
            bucket_name = name_list[0]
            object_name = '/' + name_list[1]
            if object_name.find('?') != -1:
                object_name = object_name[:object_name.find('?')]
        else:
            raise ValueError


        content += 'Bucket=%s\n' % bucket_name
        content += 'Object=%s\n' % object_name

        if time:
            flag += 'T'
            content += 'Time=%s\n' % time

        if ip:
            flag += 'I'
            content += 'Ip=%s\n' % ip

        if size:
            flag +='S'
            content += 'Size=%s\n' % size

        content = '\n'.join([flag,content])


        digest = hmac.new(b(secret_key), b(content), sha1).digest()
        signature = urlquote(base64.b64encode(digest),safe='/:')
        sign = '%s:%s:%s' % (b(flag), b(self.user_id), b(signature))
        sign = sign.decode('utf-8')
        return sign


    def connect(self, host=None, port=None, base_url=None):
        connection = None
        secure = self.secure

        host = host or self.host

        connection = self.conn_classes[secure](host)

        self.connection = connection


    def request(self, action, params=None, data=None, headers=None,
                method='GET', raw=False):
        """
        Request a given `action`.

        Basically a wrapper around the connection
        object's `request` that does some helpful pre-processing.

        :type action: ``str``
        :param action: A path. This can include arguments. If included,
            any extra parameters are appended to the existing ones.

        :type params: ``dict``
        :param params: Optional mapping of additional parameters to send. If
            None, leave as an empty ``dict``.

        :type data: ``unicode``
        :param data: A body of data to send with the request.

        :type headers: ``dict``
        :param headers: Extra headers to add to the request
            None, leave as an empty ``dict``.

        :type method: ``str``
        :param method: An HTTP method such as "GET" or "POST".

        :type raw: ``bool``
        :param raw: True to perform a "raw" request aka only send the headers
                     and use the rawResponseCls class. This is used with
                     storage API when uploading a file.

        :return: An :class:`Response` instance.
        :rtype: :class:`Response` instance

        """
        if params is None:
            params = {}
        else:
            params = copy.copy(params)

        if headers is None:
            headers = {}
        else:
            headers = copy.copy(headers)

        action = self.morph_action_hook(action)
        self.action = action
        self.method = method

        # Extend default parameters
        params = self.add_default_params(params)

        # Add cache busting parameters (if enabled)
        if self.cache_busting and method == 'GET':
            params = self._add_cache_busting_to_params(params=params)

        # Extend default headers
        headers = self.add_default_headers(headers)

        # We always send a user-agent header
        headers.update({'User-Agent': self._user_agent()})

        headers.update({'Accept': '*/*'})
        port = int(self.port)

        if port not in (80, 443):
            headers.update({'Host': "%s:%d" % (self.host, port)})
        else:
            headers.update({'Host': self.host})

        if data:
            data = self.encode_data(data)
            headers['Content-Length'] = str(len(data))
        elif method.upper() in ['POST', 'PUT'] and not raw:
            # Only send Content-Length 0 with POST and PUT request.
            #
            # Note: Content-Length is not added when using "raw" mode means
            # means that headers are upfront and the body is sent at some point
            # later on. With raw mode user can specify Content-Length with
            # "data" not being set.
            headers['Content-Length'] = '0'

        params, headers = self.pre_connect_hook(params, headers)

        if params:
            url_params = 'sign=%s' % params.pop('sign')
            for key in params.keys():
                url_params += '&%s=%s' % (key, params[key])
            if '?' in action:
                url = '&'.join((action, url_params))
            else:
                url = '?'.join((action, url_params))

                #url = '?'.join((action, urlencode(params, doseq=True)))
        else:
            url = action

        # Removed terrible hack...this a less-bad hack that doesn't execute a
        # request twice, but it's still a hack.
        self.connect()
        try:
            # @TODO: Should we just pass File object as body to request method
            # instead of dealing with splitting and sending the file ourselves?
            if raw:
                self.connection.putrequest(method, url,
                        skip_host=True, skip_accept_encoding=True)
                for key, value in list(headers.items()):
                    self.connection.putheader(key, str(value))

                self.connection.endheaders()
            else:
                #print 'url:',url
                #print 'data:',data
                #print 'headers:',headers
                self.connection.request(method=method, url=url, body=data,
                                        headers=headers)
        except ssl.SSLError:
            e = sys.exc_info()[1]
            self.reset_context()
            raise ssl.SSLError(str(e))

        if raw:
            responseCls = self.rawResponseCls
            kwargs = {'connection': self}
        else:
            responseCls = self.responseCls
            kwargs = {'connection': self,
                      'response': self.connection.getresponse()}

        try:
            response = responseCls(**kwargs)
        finally:
            # Always reset the context after the request has completed
            self.reset_context()
        return response



class BCSStorageDriver(StorageDriver):
    name = 'Baidu Cloud Storage Service'
    website = 'http://developer.baidu.com/bae/bcs'
    connectionCls = BCSConnection
    hash_type = 'md5'
    namespace = ''
    supports_chunked_encoding = False
    support_s3_multipart_upload = False
    http_vendor_prefix = 'x-bcs'

    def iterate_containers(self):
        response = self.connection.request('/')

        if response.status == httplib.NO_CONTENT:
            return []
        elif response.status == httplib.OK:
            return self._to_container_list(json.loads(response.body))

        raise LibcloudError('Unexpected status code: %s' % (response.status))

    def get_container(self, container_name):
        container_name_encoded = self._encode_container_name(container_name)
        response = self.connection.request('/%s' % (container_name_encoded),
                                           method='GET')
        if response.status == httplib.OK:
            return Container(name=container_name, extra=None, driver=self)
        elif response.status == httplib.FORBIDDEN:
            raise ContainerDoesNotExistError(None, self, container_name)

        raise LibcloudError('Unexpected status code: %s' % (response.status))

    def create_container(self, container_name):
        container_name_encoded = self._encode_container_name(container_name)
        response = self.connection.request(
            '/%s' % (container_name_encoded), method='PUT')
        if response.status == httplib.OK:
            # Accepted mean that container is not yet created but it will be
            # eventually
            extra = {'object_count': 0}
            container = Container(name=container_name,
                                  extra=extra, driver=self)

            return container
        elif response.status == httplib.FORBIDDEN:
            error = ContainerAlreadyExistsError(None, self, container_name)
            raise error

        raise LibcloudError('Unexpected status code: %s' % (response.status))

    def delete_container(self, container):
        name = self._encode_container_name(container.name)

        # Only empty container can be deleted
        response = self.connection.request('/%s' % (name), method='DELETE')

        if response.status == httplib.OK:
            return True
        elif response.status == httplib.FORBIDDEN:
            start_tag = response.body.find('code') + 7
            end_tag = response.body.find('Message') - 3
            error_code = int(response.body[start_tag:end_tag])
            if error_code == -42:
                raise ContainerDoesNotExistError(value='',
                                             container_name=name, driver=self)
            if error_code == -1007:
                raise ContainerIsNotEmptyError(value='',
                                           container_name=name, driver=self)

    def list_container_objects(self, container, ex_prefix=None):
        """
        Return a list of objects for the given container.

        :param container: Container instance.
        :type container: :class:`Container`

        :param ex_prefix: Only get objects with names starting with ex_prefix
        :type ex_prefix: ``str``

        :return: A list of Object instances.
        :rtype: ``list`` of :class:`Object`
        """
        return list(self.iterate_container_objects(container,
                                                   ex_prefix=ex_prefix))

    def iterate_container_objects(self, container, ex_prefix=None):
        """
        Return a generator of objects for the given container.

        :param container: Container instance
        :type container: :class:`Container`

        :param ex_prefix: Only get objects with names starting with ex_prefix
        :type ex_prefix: ``str``

        :return: A generator of Object instances.
        :rtype: ``generator`` of :class:`Object`
        """
        params = {}
        if ex_prefix:
            params['prefix'] = ex_prefix

        while True:
            container_name_encoded = \
                self._encode_container_name(container.name)
            response = self.connection.request('/%s' %
                                               (container_name_encoded),
                                               params=params)

            if response.status == httplib.NO_CONTENT:
                # Empty or non-existent container
                break
            elif response.status == httplib.OK:
                objects = self._to_object_list(json.loads(response.body),
                                               container)

                if len(objects) == 0:
                    break

                for obj in objects:
                    yield obj
                params['marker'] = obj.name
                break

            else:
                raise LibcloudError('Unexpected status code: %s' %
                                    (response.status))


    def get_object(self, container_name, object_name):
        """
        HTTP method in get_object() is 'HEAD'.This method only get the metadata of object, won't download object content.
        """
        container = self.get_container(container_name)
        container_name_encoded = self._encode_container_name(container_name)
        object_name_encoded = self._encode_object_name(object_name)

        response = self.connection.request('/%s/%s' % (container_name_encoded,
                                                       object_name),
                                           method='HEAD')
        if response.status == httplib.OK:
            obj = self._headers_to_object(
                object_name, container, response.headers)
            return obj
        elif response.status == httplib.NOT_FOUND:
            raise ObjectDoesNotExistError(None, self, object_name)

        raise LibcloudError('Unexpected status code: %s' % (response.status))

    def download_object(self, obj, destination_path, overwrite_existing=False,
                        delete_on_failure=True):
        container_name = obj.container.name
        object_name = obj.name
        response = self.connection.request('/%s/%s' % (container_name,
                                                       object_name),
                                           method='GET',raw=True)
        return self._get_object(
            obj=obj, callback=self._save_object, response=response,
            callback_kwargs={'obj': obj,
                             'response': response.response,
                             'destination_path': destination_path,
                             'overwrite_existing': overwrite_existing,
                             'delete_on_failure': delete_on_failure},
            success_status_code=httplib.OK)

    def download_object_as_stream(self, obj, chunk_size=None):
        container_name = obj.container.name
        object_name = obj.name
        response = self.connection.request('/%s/%s' % (container_name,
                                                       object_name),
                                           method='GET', raw=True)

        return self._get_object(obj=obj, callback=read_in_chunks,
                                response=response,
                                callback_kwargs={'iterator': response.response,
                                                 'chunk_size': chunk_size},
                                success_status_code=httplib.OK)

    def upload_object(self, file_path, container, object_name, extra=None,
                      verify_hash=True):
        """
        Upload an object.

        Note: This will override file with a same name if it already exists.
        """
        upload_func = self._upload_file
        upload_func_kwargs = {'file_path': file_path}

        return self._put_object(container=container, object_name=object_name,
                                upload_func=upload_func,
                                upload_func_kwargs=upload_func_kwargs,
                                extra=extra, file_path=file_path,
                                verify_hash=verify_hash)

    def upload_object_via_stream(self, iterator,
                                 container, object_name, extra=None):
        if isinstance(iterator, file):
            iterator = iter(iterator)

        upload_func = self._stream_data
        upload_func_kwargs = {'iterator': iterator}

        return self._put_object(container=container, object_name=object_name,
                                upload_func=upload_func,
                                upload_func_kwargs=upload_func_kwargs,
                                extra=extra, iterator=iterator)


    def delete_object(self, obj):
        container_name = self._encode_container_name(obj.container.name)
        object_name = self._encode_object_name(obj.name)

        response = self.connection.request(
            '/%s/%s' % (container_name, object_name), method='DELETE')

        if response.status == httplib.OK:
            return True
        elif response.status == httplib.NOT_FOUND:
            raise ObjectDoesNotExistError(value='', object_name=object_name,
                                          driver=self)

        raise LibcloudError('Unexpected status code: %s' % (response.status))

    def copy_object(self, dst_container, dst_object, src_container,
            src_object):
        src_container_name = self._encode_container_name(src_container)
        src_object_name = self._encode_object_name(src_object)
        dst_container_name = self._encode_container_name(dst_container)
        dst_object_name = self._encode_object_name(dst_object)

        headers = {}
        headers['x-bs-copy-source'] = 'http://%s/%s/%s' % \
                       (self.connection.host, src_container_name, src_object_name)
        if src_container_name == dst_container_name and \
            src_object_name == dst_object_name:
                headers['x-bs-copy-source-directive'] = 'replace'

        response = self.connection.request('/%s/%s' %
                (dst_container_name, dst_object_name), method='PUT',
                headers=headers)

        if response.status == httplib.OK:
            return True

        raise LibcloudError('Unexpected status code: %s' % (response.status))

    #_upload_object_part() for large file
    def put_superfile(self, container_name, object_name, object_list):
        container_name_encoded = self._encode_container_name(container_name)
        object_name_encoded = self._encode_object_name(object_name)

        count = 0
        tmp_list = []
        for obj in object_list:
            part_object_url = '%s/%s/%s' % ('bs:/', obj.container.name, obj.name)
            tmp_list.append('"part_%d":{"url":"%s", "etag":"%s"}' % (count,
                part_object_url, obj.hash))

            count += 1


        super_file_meta = '{"object_list":{%s}}' % ','.join(tmp_list)

        response = self.connection.request('/%s/%s?superfile=1' %
                (container_name_encoded, object_name_encoded),
                method='PUT', data=super_file_meta)

        if response.status == httplib.OK:
            return True

        raise LibcloudError('Unexpected status code: %s' % (response.status))


    def _put_object(self, container, object_name, upload_func,
                    upload_func_kwargs, extra=None, file_path=None,
                    iterator=None, verify_hash=True):
        extra = extra or {}
        container_name_encoded = self._encode_container_name(container.name)
        object_name_encoded = self._encode_object_name(object_name)
        content_type = extra.get('content_type', None)
        meta_data = extra.get('meta_data', None)
        content_disposition = extra.get('content_disposition', None)

        headers = {}
        if meta_data:
            for key, value in list(meta_data.items()):
                key = 'x-bs-meta-%s' % (key)
                headers[key] = value

        if content_disposition is not None:
            headers['Content-Disposition'] = content_disposition

        request_path = '/%s/%s' % (container_name_encoded, object_name_encoded)
        result_dict = self._upload_object(
            object_name=object_name, content_type=content_type,
            upload_func=upload_func, upload_func_kwargs=upload_func_kwargs,
            request_path=request_path, request_method='PUT',
            headers=headers, file_path=file_path, iterator=iterator)

        response = result_dict['response'].response
        bytes_transferred = result_dict['bytes_transferred']
        server_hash = result_dict['response'].headers.get('etag', None)

        if response.status == httplib.EXPECTATION_FAILED:
            raise LibcloudError(value='Missing content-type header',
                                driver=self)
        elif verify_hash and not server_hash:
            raise LibcloudError(value='Server didn\'t return etag',
                                driver=self)
        elif (verify_hash and result_dict['data_hash'] != server_hash):
            raise ObjectHashMismatchError(
                value=('MD5 hash checksum does not match (expected=%s, ' +
                       'actual=%s)') % (result_dict['data_hash'], server_hash),
                object_name=object_name, driver=self)
        elif response.status == httplib.OK:
            obj = Object(
                name=object_name, size=bytes_transferred, hash=server_hash,
                extra=None, meta_data=meta_data, container=container,
                driver=self)

            return obj
        else:
            # @TODO: Add test case for this condition (probably 411)
            raise LibcloudError('status_code=%s' % (response.status),
                                driver=self)

    def _headers_to_object(self, name, container, headers):
        size = int(headers.pop('content-length', 0))
        last_modified = headers.pop('last-modified', None)
        etag = headers.pop('etag', None)
        content_type = headers.pop('content-type', None)

        meta_data = {}
        for key, value in list(headers.items()):
            if key.find('x-bs-meta-') != -1:
                key = key.replace('x-bs-meta-', '')
                meta_data[key] = value

        extra = {'content_type': content_type, 'last_modified': last_modified}

        obj = Object(name=name, size=size, hash=etag, extra=extra,
                     meta_data=meta_data, container=container, driver=self)
        return obj

    def _to_container_list(self, response):
        # @TODO: Handle more than 10k containers - use "lazy list"?
        for container in response:
            extra = {'cdatetime': int(container['cdatetime']),
                     'status':int(container['status']),
                     'size':int(container['used_capacity']),
                     'region': container['region']}
            yield Container(name=container['bucket_name'], extra=extra, driver=self)

    def _encode_container_name(self, name):
        """
        Encode container name so it can be used as part of the HTTP request.
        """
        if name.startswith('/'):
            name = name[1:]

        if name.startswith('-') or name.endswith('-'):
            raise InvalidContainerNameError(value='Container name cannot'
                                                  ' start or end with -',
                                            container_name=name, driver=self)

        if name[0].isdigit():
            raise InvalidContainerNameError(value='Container name cannot'
                                                  ' start with number',
                                           container_name=name, driver=self)

        if len(name) < 6 or len(name) > 63:
            raise InvalidContainerNameError(value='Container name length'
                                                  ' must between 6 and 63',
                                            container_name=name, driver=self)

        pattern = re.compile('[a-z0-9/-]+')
        m = pattern.match(name)
        if not m or m.group() != name:
            raise InvalidContainerNameError(value='Container name'
                                                  ' must be made up with numbers, lower letters and -', container_name=name, driver=self)

        return name

    def _encode_object_name(self, name):
        if len(name) >255:
            raise InvalidObjectNameError(value='Object name length must'
                                               ' less than 255',
                                        object_name=name, driver=self)

        name = urlquote(name)
        return name


    def _to_object_list(self, response, container):
        objects = []
        for obj in response['object_list']:
            name = obj['object']
            size = int(obj['size'])
            hash = obj['content_md5']
            extra = {'ref_key': obj['ref_key'],
                     'version_key': obj['version_key'],
                     'superfile': obj['superfile']}
            meta_data = {'is_dir': int(obj['is_dir']),
                         'parent_dir': obj['parent_dir'],
                         'mdatetime': obj['mdatetime']}
            objects.append(Object(
                name=name, size=size, hash=hash, extra=extra,
                meta_data=meta_data, container=container, driver=self))

        return objects

