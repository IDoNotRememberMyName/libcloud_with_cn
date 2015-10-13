import hmac
import copy
import ssl
import sys
import time
import urllib
import os
import requests
import tempfile

try:
    import simplejson as json
except (ImportError,SyntaxError):
    import json

from hashlib import sha1
from libcloud.utils.py3 import httplib
from libcloud.utils.qiniu import urlsafe_base64_encode
from libcloud.utils.qiniu_compat import b
from libcloud.common.types import InvalidCredsError,LibcloudError
from libcloud.storage.base import Object,Container
from libcloud.common.base import ConnectionUserAndKey,BaseDriver,JsonResponse,XmlResponse
from libcloud.storage.types import ContainerAlreadyExistsError
from libcloud.storage.types import ContainerDoesNotExistError
from libcloud.storage.types import ContainerIsNotEmptyError
from libcloud.storage.types import ObjectDoesNotExistError
from libcloud.storage.types import ObjectHashMismatchError
from libcloud.storage.types import InvalidContainerNameError
from libcloud.storage.types import InvalidObjectNameError

QINIU_HOST1 = 'rs.qiniu.com'
QINIU_HOST2 = 'rsf.qbox.me'
HTTP_VERSION = 'HTTP/1.1'

class QiNiuResponse(JsonResponse):
    pass

class QNConnection(ConnectionUserAndKey):
    """
    Represents a single connection to the qiniu OSS Endpoint
    """
    host = QINIU_HOST1
    query = None
    secure = False
    responseCls = QiNiuResponse

    def __init__(self,user_id,key,secure=False,host=None,port=None,url=None,timeout=None,proxy_url=None):
        super(QNConnection,self).__init__(user_id,key,secure=False,host=host,port=port,url=url,timeout=timeout,proxy_url=proxy_url)

    def request(self,action,params=None,data=None,headers=None,method='GET',raw=False,args=None,iterator=None):

       QNConnection.host = QINIU_HOST1
       action = self.morph_action_hook(action)
       self.action = action
       self.method = method
       files = None
       # accoding params type to decide the url(some need encode some not)

       if params is None:
           params = {}
           url = action
       elif type(params) is type(['a','b']):
           container_name = params[0]
           params = copy.copy(params)
           # Extend default parameters
           params = self.add_default_params(params)
           if params:
               url = '/'.join((action,params))
           else:
               url = action
           if action == '/v6/domain/list?tbl=':
               url = action+container_name
               QNConnection.host = 'api.qiniu.com'
       elif type(params) is type({'a':'b'}):
           QNConnection.host = QINIU_HOST2
           params = self.change_default_params(params)
           if params:
               url = '?'.join((action,params))
           else:
               url = action

       # add something in headers
       if headers is None:
           headers = {}
       else:
           headers = copy.copy(headers)

       # Extend default headers except for upload_file
       if action is not ('/'):
           headers = self.add_default_headers(headers,url)

       # We always send a user-agent headers
       headers.update({'User-Agent':self._user_agent()})

       headers.update({'Accept-Encoding':'gizp,deflate,compress'})

       if action == '/list':
           headers.update({'Content-Type':'application/w-www-form-urlencoded'})
       else:
           headers.update({'Content-Type':'application/json'})

       port = int(self.port)

       if port not in (80,443):
           headers.update({'Host': "%s:%d" %(self.host,port)})
       else:
           headers.update({'Host': self.host})

       # when upload_file,file`s content and something as body
       if data:
           token = self.get_uploadToken(data)
           body = self.add_default_data(token,args)
           if args['file_path']:
               headers['Content-Length'] = os.stat(args['file_path']).st_size
           name = args['file_name'] if args['file_name'] else 'file_name'
           if args['file_path']:
               data = open(args['file_path'],'rb')
           else:
               data = iterator
           files={'file':(name,data,args['mime_type'])}
       elif method.upper() in ['POST','PUT'] and not raw:
           headers['Content-Length'] = '0'

       #connect

       if action == '/':
           try:
               _session=requests.Session()
               r= _session.post(url='http://upload.qiniu.com/',data=body,files=files,headers=None)
               if r.status_code != 200:
                   return r.status_code
           except:
               r.status_code = -1
           ret = r.json() if r.text != '' else {}
           return r
       else:
           self.connect()
           try:
               if raw:
                   self.connection.putrequest(method,url)
                   for key, value in list(headers.items()):
                       self.connection.putheader(key,str(value))

                   self.connection.endheaders()

               else:
                   self.connection.request(method=method,url=url,body=data,headers=headers)
           except ssl.SSLError:
               e = sys.exc_info()[1]
               self.reset_context()
               raise ssl.SSLError(str(e))

           if raw:
               responseCls = self.rawResponseCls
               kwargs = {'connection':self}
           else:
               responseCls = self.responseCls
               kwargs = {'connection':self,'response':self.connection.getresponse()}

           try:
               response = responseCls(**kwargs)
           finally:
               self.reset_context()

           return response

    def add_default_params(self,params):
        if params[1] is None:
            params = urlsafe_base64_encode('{0}'.format(params[0]))
        else:
            params = urlsafe_base64_encode('{0}:{1}'.format(params[0],params[1]))
        return params

    def change_default_params(self,params):
        query = ''
        i=0
        for items in params:
            if i == 0:
                query = ''.join([items,'=',params[items]])
            else:
                query = ''.join([query,'&',items,'=',params[items]])
            i=1
        return query

    def add_default_headers(self,headers,url):
        url = ''.join([url,'\n'])
        token = self.get_token(url)
        Authorization = 'QBox '+ token
        headers['Authorization'] = Authorization
        headers['Accept'] = '*/*'
        return headers

    def get_token(self,params):
        signingStr = params
        signingStr = b(signingStr)
        sign = hmac.new(self.key,signingStr,sha1)
        encodedSign = urlsafe_base64_encode(sign.digest())
        accessToken = '{0}:{1}'.format(self.user_id,encodedSign)
        return accessToken

    def add_default_data(self,token,args):
        data = {}
        if args['file_name'] is not None:
            data['key'] = args['file_name']
        data['token'] = token
        return data

    def get_uploadToken(self,putPolicy):
        data = json.dumps(putPolicy,separators=(',',':'))
        encodedPutPolicy = urlsafe_base64_encode(data)
        accessToken = self.get_token(encodedPutPolicy)
        uploadToken = '{0}:{1}'.format(accessToken,encodedPutPolicy)
        return uploadToken



class QiNiuStorageDriver(BaseDriver):
    name = 'qiniu cloudStorge service'
    website = 'http://www.qiniu.com/'

    connectionCls = QNConnection

    # functions of Containers

    def create_container(self,container_name):
        try:
            con_name = self._list_containers()
            if container_name  in str(con_name):
                raise LibcloudError('the container is existed! Please rename the file')
                return None

            action = '/mkbucket/%s' %(container_name)
            response = self.connection.request(method='POST',action=action)

            if response.status == httplib.OK:
                extra = {'object_count':0}
                container = Container(name=container_name,extra=extra,driver=self)
                return container
            elif response.status == httplib.NOT_FOUND:
                error = ContainerAlreadyExistsError(None,self,container_name)
                raise error
            raise LibcloudError('Unexpected status code: %s' % (response.status))
        except InvalidCredsError:
            pass

    def delete_container(self,container):
        try:
            container_name = container.name
            action = '/drop/%s' %(container_name)
            response = self.connection.request(method='POST',action=action)
            if response.status == httplib.OK:
                return True
            elif response.status == httplib.NOT_FOUND:
                raise ContainerDoesNotExistError(value=None,driver=self,container_name=container_name)
        except InvalidCredsError:
            pass

    def list_containers(self):
        response = self.connection.request(action='/buckets')
        if response.status == httplib.NO_CONTENT:
            return []
        elif response.status == httplib.OK:
            return self._to_container_list(json.loads(response.body))

        raise LibcloudError('Unexpected status code: %s' % (response.status))


    def _list_containers(self):
        response = self.connection.request(action='/buckets')
        if response.status == httplib.NO_CONTENT:
            return []
        elif response.status == httplib.OK:
            return response.body


    def get_container(self,container_name):
        return Container(name=container_name,extra=None,driver=self)

    # functions of objects

    def get_object(self,container_name,file_name):
        try:
            entry = [container_name,file_name]
            response = self.connection.request(action='/stat',params=entry)

            if response.status == httplib.NOT_FOUND:
               raise ContainerDoesNotExistError(value=None,driver=self,container_name=container_name)

            val = response.body.split(',')
            fsize = val[0].split(':')[1]
            res_hash = val[1].split(':')[1]
            container = self.get_container(container_name)
            return Object(file_name,fsize,res_hash,extra=None,meta_data=None,container=container,driver=self)
        except InvalidCredsError:
            pass


    def delete_object(self,obj):
        try:
            file_name = obj.name
            container_name = obj.container.name
            entry = [container_name,file_name]
            response = self.connection.request(method='POST',action='/delete',params=entry)

            if response.status == httplib.OK:
                return True
            elif response.status == httplib.NOT_FOUND:
                raise ObjectDoesNotExistError(value='',driver=self,object_name=file_name)

            raise LibcloudError('Unexpected status code: %s' % (response.status))
        except InvalidCredsError:
            pass

    def list_container_objects(self,container,prefix=None,marker=None,limit=None,delimiter=None):
        try:
            container_name = container.name
            entry = {'bucket':container_name,}
            if marker is not None:
                entry['marker'] = marker
            if limit is not None:
                entry['limit'] = limit
            if prefix is not None:
                entry['prefix'] = prefix
            if delimiter is not None:
                entry['delimiter'] = delimiter

            response = self.connection.request(method='POST',action='/list',params=entry)
            if response.status == httplib.OK:
                objects = self._to_object_list(json.loads(response.body),container)
                return list(objects)
            else:
                raise LibcloudError('Unexpected status code: %s' % (response.status))
        except InvalidCredsError:
            pass


    def download_object(self,container,file_path,expires=3600):
        file_name = file_path.split('/')[-1]
        container_name = container.name
        bucket_domain=self._domain_list(container_name)[2:-2]
        print 'bucket_domain',bucket_domain
        url = 'http://%s/%s' %(bucket_domain,file_name)
        deadline = int(time.time()) + expires
        if '?' in url:
            url += '&'
        else:
            url += '?'
        url = '{0}e={1}'.format(url,str(deadline))
        try:
            name = self.list_container_objects(container)
            if file_name not in str(name):
                print 'the text is not existed!'
                return False
            token = self.connection.get_token(url)
            url = '{0}&token={1}'.format(url,token)
            file = urllib.urlopen(url).read()
            fobj = open(file_path,'w')
            fobj.write(file)
            return True
        except InvalidCredsError:
            pass


    def download_object_as_stream(self,obj,chunk_size=None,expires=3600):
        container_name = obj.container.name
        file_name = obj.name
        bucket_domain=self._domain_list(container_name)[2:-2]
        url = 'http://%s/%s' %(bucket_domain,file_name)
        deadline = int(time.time()) + expires
        if '?' in url:
            url += '&'
        else:
            url += '?'
        url = '{0}e={1}'.format(url,str(deadline))
        try:
            name = self.list_container_objects(obj.container)
            if file_name not in str(name):
                print 'the text is not existed!'
                return False
            token = self.connection.get_token(url)
            url = '{0}&token={1}'.format(url,token)
            file = urllib.urlopen(url).read()
            temp = tempfile.TemporaryFile()
            temp.write(file)
            temp.seek(0)
            return temp
        except InvalidCredsError:
            return False

    def upload_object(self,file_path,container,file_name=None,expires=3600):
        try:
            container_name = container.name
            if container_name is None or container_name == '':
                raise ValueError('invalid bucket name')
            scope = container_name
            if file_path is not None and file_name is None:
                file_name = file_path.split('/')[-1]

            name = self.list_container_objects(container)
            if file_name  in str(name):
                raise LibcloudError('the text is existed! Please rename the file')
                return None

            scope = '{0}:{1}'.format(container_name,file_name)

            data = dict(
                    scope = scope,
                    deadline = int(time.time()) + expires,
                    )

            args = {'file_path':file_path,'file_name':file_name,'mime_type':'text/plain'}
            response = self.connection.request(method='POST',action='/',data=data,args=args)

            if response.status_code == httplib.OK:
                obj = self.get_object(container_name,file_name)
                return obj
            else:
                raise LibcloudError('Unexpected status code: %s' % (response.status))
        except InvalidCredsError:
            pass


    def upload_object_via_stream(self,iterator,container,object_name,extra=None,expires=3600):

        try:
           if isinstance(iterator,file):
               iterator = iter(iterator)
               container_name = container.name

               name = self.list_container_objects(container)
               if object_name  in str(name):
                    #print 'the text is existed! Please rename the file'
                    raise LibcloudError('the text is existed! Please rename the file')
                    return None

               if container_name is None or container_name == '':
                   raise ValueError('invalid bucket name')
               scope = container_name
               scope = '{0}:{1}'.format(container_name,object_name)

               data = dict(
                           scope = scope,
                           deadline = int(time.time()) + expires,
                          )

               args = {'file_path':None,'file_name':object_name,'mime_type':'text/plain'}
               response = self.connection.request(method='POST',action='/',data=data,args=args,iterator=iterator)

               if response.status_code == httplib.OK:
                   obj = self.get_object(container_name,object_name)
                   return obj
               else:
                   raise LibcloudError('Unexpected status code: %s' % (response.status))
        except InvalidCredsError:
            pass


    def _domain_list(self,container_name):
        entry = [container_name,'']
        try:
            response = self.connection.request(action='/v6/domain/list?tbl=',params=entry)
            if response.status == httplib.NOT_FOUND:
                raise ContainerDoesNotExistError(value=None,driver=self,container_name=container_name)
        except InvalidCredsError:
            pass
        return response.body


    def _to_container_list(self,response):
        for container in response:
            yield Container(name=container,extra=None,driver=self)

    def _to_object_list(self,response,container):
        objects = []
        for obj in response['items']:
            name = obj['key']
            size = int(obj['fsize'])
            hash = obj['hash']
            extra = {'mimeType':obj['mimeType'],'putTime':obj['putTime']}
            objects.append(Object(name=name,size=size,hash=hash,extra=extra,meta_data=None,container=container,driver=self))
        return objects


