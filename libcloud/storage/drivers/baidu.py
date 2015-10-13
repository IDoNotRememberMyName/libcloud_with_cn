import re
import datetime
import sys
import copy
import hashlib
import hmac
try:
    import simplejson as json
except ImportError:
    import json

from libcloud.utils.files import read_in_chunks, guess_file_mime_type
from libcloud.storage.base import Object, Container, StorageDriver
from libcloud.common.base import JsonResponse, RawResponse, ConnectionUserAndKey
from libcloud.storage.drivers.s3 import BaseS3StorageDriver, S3Response, S3RawResponse
from libcloud.storage.drivers.cloudfiles import CloudFilesStorageDriver
from libcloud.utils.py3 import httplib
from libcloud.utils import util
from libcloud.utils.py3 import urlquote

from libcloud.common.types import MalformedResponseError, LibcloudError
from libcloud.storage.types import ObjectHashMismatchError,ObjectDoesNotExistError
from libcloud.storage.types import InvalidContainerNameError,InvalidObjectNameError
from libcloud.storage.types import ContainerAlreadyExistsError,ContainerDoesNotExistError
from libcloud.storage.types import ContainerIsNotEmptyError

BOS_HOST = 'bj.bcebos.com'
PROXY_HOST = 'localhost:8080'
SDK_VERSION = '0.8.4'
BOS_DATE = "x-bce-date"
AUTHORIZATION = "Authorization"
EXPIRATION_SECOND = 15 * 60
BCE_PREFIX = "x-bce-"

class BOSResponse(JsonResponse):
    valid_response_codes = [httplib.NOT_FOUND, httplib.FORBIDDEN,
            httplib.CONFLICT,httplib.BAD_REQUEST,httplib.NO_CONTENT]

    def success(self):
        i = int(self.status)
        return i == 200 or i == 204 or i in self.valid_response_codes

class BOSRawResponse(BOSResponse, RawResponse):
    pass

class BOSConnection(ConnectionUserAndKey):
    host = BOS_HOST
    expire_time_flag = False
    ip = None
    size = None
    responseCls = BOSResponse
    rawresponseCls = BOSRawResponse

    def get_canonical_headers(self,headers, headers_to_sign = None):
        headers = headers or {}
        if headers_to_sign is None or len(headers_to_sign) == 0:
            headers_to_sign = set(["host",
                                   "content-md5",
                                   "content-length",
                                   "content-type"])
        result = []
        for k in headers:
            k_lower = k.strip().lower()
            value = str(headers[k]).strip()
            if k_lower.startswith(BCE_PREFIX) \
                    or k_lower in headers_to_sign:
                str_tmp = "%s:%s" % (util.normalize_string(k_lower), util.normalize_string(value))
                result.append(str_tmp)
        result.sort()
        return '\n'.join(result)

    def signer(self, method, action, headers, params,
         timestamp=0, expiration_in_seconds=1800, headers_to_sign=None):
        """
        Create the authorization
        """
	print method, action, headers, params, timestamp, expiration_in_seconds, headers_to_sign

        headers = headers or {}
        params = params or {}

        sign_key_info = 'bce-auth-v1/%s/%s/%d' % (
            self.user_id,
            util.get_canonical_time(timestamp),
            expiration_in_seconds)
        sign_key = hmac.new(
            self.key,
            sign_key_info,
            hashlib.sha256).hexdigest()

        canonical_url = action
        canonical_querystring = util.get_canonical_querystring(params, True)
	canonical_headers = self.get_canonical_headers(headers, headers_to_sign)
        string_to_sign = '\n'.join(
            [method, canonical_url, canonical_querystring, canonical_headers])

        sign_result = hmac.new(sign_key, string_to_sign, hashlib.sha256).hexdigest()

        if headers_to_sign:
            result = '%s/%s/%s' % (sign_key_info, ';'.join(headers_to_sign), sign_result)
        else:
            result = '%s//%s' % (sign_key_info, sign_result)

        print 'sign_key=[%s] sign_string=[%d bytes][ %s ]' %(sign_key, len(string_to_sign), string_to_sign)
        #print 'result=%s' % result
        return result

    def request(self, action, params=None, data=None, headers=None,
                method='GET', raw=False):
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

        # Extend default headers
        headers = self.add_default_headers(headers)

        # We always send a user-agent header
	user_agent = 'bce-sdk-python/%s/%s/%s' % (SDK_VERSION, sys.version, sys.platform)
	user_agent = user_agent.replace('\n', '')
	headers.update({'User-Agent': user_agent})


        port = int(self.port)

        if port not in (80, 443):
            headers.update({'Host': "%s:%d" % (self.host, port)})
        else:
            headers.update({'Host': self.host})

	if BOS_DATE not in headers:
            utctime = datetime.datetime.utcnow()
            headers[BOS_DATE] = "%04d-%02d-%02dT%02d:%02d:%02dZ" % (utctime.year, utctime.month, utctime.day,
		utctime.hour, utctime.minute, utctime.second)

        if data:
            data = self.encode_data(data)
            headers['Content-Length'] = str(len(data))
        elif method.upper() in ['POST', 'PUT'] and not raw:
            headers['Content-Length'] = '0'
	offset = None
	if hasattr(data, "tell") and hasattr(data,"seek"):
            offset = data.tell()

        params, headers = self.pre_connect_hook(params, headers)

	if AUTHORIZATION not in headers:
            headers[AUTHORIZATION] = self.signer(method,action,headers,params)

	encoded_params = util.get_canonical_querystring(params, False)
	if len(encoded_params) > 0:
            url = action + '?' + encoded_params
	else:
            url = action

        for k, v in headers.iteritems():
            if isinstance(v, (str, unicode)) and '\n' in v:
                raise BceClientError(r'There should not be any "\n" in header[%s]:%s' % (k, v))
        # Removed terrible hack...this a less-bad hack that doesn't execute a
        # request twice, but it's still a hack.
        self.connect()
        try:
            # @TODO: Should we just pass File object as body to request method
            # instead of dealing with splitting and sending the file ourselves?
            if raw:
                self.connection.putrequest(method, url)
                for key, value in list(headers.items()):
                    self.connection.putheader(key, str(value))

                self.connection.endheaders()
            else:
                self.connection.request(method=method, url=url, body=data,
                                        headers=headers)
        except ssl.SSLError:
            e = sys.exc_info()[1]
            self.reset_context()
            raise ssl.SSLError(str(e))

        if raw:
            responseCls = self.rawResponseCls
            kwargs = {'connection': self}
            print 'raw:--------'
        else:
            responseCls = self.responseCls
            kwargs = {'response': self.connection.getresponse(),'connection': self}
            print 'not raw--------'
        try:
            response = responseCls(**kwargs)
        finally:
            # Always reset the context after the request has completed
            self.reset_context()
        return response

class BOSStorageDriver(StorageDriver):
    name = 'bos'
    website = 'http://bos.bj.baidubce.com/'
    connectionCls = BOSConnection
    hash_type = 'md5'
    RANGE = "Range"
    supports_chunked_encoding = False
    ex_blob_type = 'BlockBlob'
#   namespace must be overridden
    namespace = ''
    def iterate_containers(self):
        response = self.connection.request('/')

        if response.status == httplib.FORBIDDEN:
            raise LibcloudError('AccessDenied')
        elif response.status == httplib.OK:
            return self._to_container_list(json.loads(response.body))

        raise LibcloudError('Unexpected status code: %s' % (response.status))

    def get_container(self, container_name):
        container_name_encoded = self._encode_container_name(container_name)
        response = self.connection.request('/%s' % (container_name_encoded),
                                           method='GET')
        if response.status == httplib.OK:
            return Container(name=container_name, extra=None, driver=self)
        elif response.status == httplib.NOT_FOUND:
            raise ContainerDoesNotExistError(None, self, container_name)
	elif response.status == httplib.FORBIDDEN:
            raise LibcloudError('AccessDenied!',driver=self)

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
        elif response.status == httplib.BAD_REQUEST:
            raise LibcloudError('TooManyBuckets!',driver=self)
	elif response.status == httplib.CONFLICT:
            error = ContainerAlreadyExistsError(None, self, container_name)
            raise error

        raise LibcloudError('Unexpected status code: %s' % (response.status))

    def delete_container(self, container):
        name = self._encode_container_name(container.name)

        # Only empty container can be deleted
        response = self.connection.request('/%s' % (name), method='DELETE')

        if response.status == httplib.NO_CONTENT:
            return True
        elif response.status == httplib.FORBIDDEN:
            raise LibcloudError('AccessDenied!',driver=self)
	elif response.status == httplib.NOT_FOUND:
            raise ContainerDoesNotExistError(value='',
                                             container_name=name,driver=self)
	elif response.status == httplib.CONFLICT:
            raise ContainerIsNotEmptyError(value='',
                                           container_name=name, driver=self)
        return False

    def list_container_objects(self, container, max_keys=1000, ex_prefix=None, marker=None,delimiter=None):
        """
        Return a list of objects for the given container.

        :param container: Container instance.
        :type container: :class:`Container`

        :param ex_prefix: Only get objects with names starting with ex_prefix
        :type ex_prefix: ``str``

        :return: A list of Object instances.
        :rtype: ``list`` of :class:`Object`
        """
        return list(self.iterate_container_objects(container,max_keys=max_keys,ex_prefix=ex_prefix,marker=marker,delimiter=delimiter))

    def iterate_container_objects(self, container, max_keys=1000, ex_prefix=None, marker=None,delimiter=None):
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
	if max_keys:
            params['maxKeys'] = max_keys
        if ex_prefix:
            params['prefix'] = ex_prefix
	if marker:
            params['marker'] = marker
	if delimiter:
            params['delimiter'] = delimiter

        while True:
            container_name_encoded = \
                self._encode_container_name(container.name)
            print '~~~~~`',container_name_encoded, params
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
                #params['marker'] = obj.name
                break

            else:
                raise LibcloudError('Unexpected status code: %s' % (response.status))


    def get_object(self, container_name, object_name):
        """
        HTTP method in get_object() is 'HEAD'.This method only get the metadata of object, won't download object content.
        """
        container = self.get_container(container_name)
        container_name_encoded = self._encode_container_name(container_name)
        object_name_encoded = self._encode_object_name(object_name)


        response = self.connection.request('/%s/%s' % (container_name_encoded,object_name),method='HEAD')
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

        generator = self._get_object(obj=obj, callback=read_in_chunks,
                                response=response,
                                callback_kwargs={'iterator': response.response,
                                                 'chunk_size': chunk_size},
                                success_status_code=httplib.OK)
	return generator

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

        if response.status == httplib.OK or response.status == 204:
            return True
        elif response.status == httplib.NOT_FOUND:
            raise ObjectDoesNotExistError(value='', object_name=object_name,
                                          driver=self)

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
                key = 'x-bce-meta-%s' % (key)
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
        server_hash = result_dict['response'].headers.get('etag', None).split('"')[1]
        print '--test--',result_dict['data_hash'],server_hash,type(result_dict['data_hash']),type(server_hash)
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
            if key.find('x-bce-meta-') != -1:
                key = key.replace('x-bce-meta-', '')
                meta_data[key] = value

        extra = {'content_type': content_type, 'last_modified': last_modified}

        obj = Object(name=name, size=size, hash=etag, extra=extra,
                     meta_data=meta_data, container=container, driver=self)
        return obj

    def _encode_container_name(self, name):
        """
        Encode container name so it can be used as part of the HTTP request.
        """

        if not name[0].isdigit() and not name[0].isalpha():
            raise InvalidContainerNameError(value='Container name must'
                                                  ' start with number or letter',
                                           container_name=name, driver=self)
        if not name[-1].isdigit() and not name[-1].isalpha():
            raise InvalidContainerNameError(value='Container name must'
                                                  ' end with number or letter',
                                           container_name=name, driver=self)

        if len(name) < 3 or len(name) > 63:
            raise InvalidContainerNameError(value='Container name length'
                                                  ' must between 3 and 63',
                                            container_name=name, driver=self)

        pattern = re.compile('[a-z0-9]+')
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

    def _to_container_list(self, response):
        # @TODO: Handle more than 10k containers - use "lazy list"?
        for container in response['buckets']:
            name = container['name']
            extra = {'creationDate': container['creationDate'],
                     'location': container['location']}
            yield Container(name=name, extra=extra, driver=self)

    def _to_object_list(self, response, container):
        objects = []
	print '---',response
        for obj in response['contents']:
            name = obj['key']
            size = int(obj['size'])
            hash = obj['eTag']
            extra = {'lastModified': obj['lastModified']}

            meta_data = {'owner':{'id':obj['owner']['id'],'displayName':obj['owner']['displayName']}}
            objects.append(Object(
                name=name, size=size, hash=hash, extra=extra,
                meta_data=meta_data, container=container, driver=self))

        return objects

