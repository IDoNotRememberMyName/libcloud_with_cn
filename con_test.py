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

import ConfigParser
from time import time
from pprint import pprint

from libcloud.storage.types import Provider
from libcloud.storage.providers import get_driver
from libcloud.storage.base import Container,Object

FILE_PATH = '/root/cloud_basic.conf'

def get_access_key(path,cloud_name):
    cf = ConfigParser.ConfigParser()
    cf.read(path)
    try:
        access_key_id = cf.get(cloud_name,'accesskeyid')
        access_key_secret = cf.get(cloud_name,'accesskeysecret')
    except ConfigParser.NoSectionError, ConfigParser.NoOptionError:
        raise
    return access_key_id,access_key_secret


def basic_container_test(provider_name,access_key_id,access_key_secret,**kwargs):
    CloudDriver = get_driver(provider_name)
    if kwargs == {}:
        driver = CloudDriver(access_key_id, access_key_secret,secure=False)
    else:
        driver = CloudDriver(access_key_id, secret=access_key_secret, secure=kwargs['secure'],
                host=kwargs['host'], port=kwargs['port'])

    containers = driver.list_containers()
    pprint(containers)
    container_objects = driver.list_container_objects(containers[0])
    pprint(container_objects)

def put_container_test(driver, container_name):
    container = driver.create_container(container_name)

if __name__ == "__main__":
    #access_key_id,access_key_secret = get_access_key(FILE_PATH,'Amazon S3')
    #print access_key_id
    #print access_key_secret
    #basic_container_test(Provider.S3,access_key_id,access_key_secret)

    #user_name,passwd = get_access_key(FILE_PATH,'Openstack Swift')
    #tenant_name,user_id = user_name.split(':')

    #CloudDriver = get_driver(Provider.CLOUDFILES_SWIFT)
    #driver = CloudDriver(user_id, passwd,secure=False,
    #        region='RegionOne',ex_tenant_name=tenant_name,ex_force_auth_url='http://192.168.137.201:35357',ex_force_auth_version='2.0_password',ex_force_service_type='object-store',ex_force_service_name='Swift')
    #containers = driver.list_containers()
    #pprint(containers)

    #access_key_id,access_key_secret = get_access_key(FILE_PATH,'Ali OSS')
    #CloudDriver = get_driver(Provider.ALI_OSS)
    #driver = CloudDriver(access_key_id,access_key_secret)
    #containers = driver.list_containers()
    #container_objects = driver.list_container_objects(containers[0])
    #pprint(containers)
    #pprint(container_objects)
    access_key_id,access_key_secret = get_access_key(FILE_PATH,'Baidu')
    #basic_container_test(Provider.BAIDU,access_key_id,access_key_secret)
    CloudDriver = get_driver(Provider.BAIDU)
    driver = CloudDriver(access_key_id, access_key_secret,secure=False)
    #delete_container = Container(name='hbcloud', extra=None, driver=driver)
    #driver.delete_container(delete_container)
    #containers = driver.list_containers()
    #containers = driver.get_container('hbcloud')
    #pprint(containers)
    #objects = driver.get_object('hbcloud','copy.py')
    #pprint(objects)
    #objects1 = driver.get_object('hbcloud','setup.py')
    #pprint(objects1)
    #res = driver.put_superfile('hbcloud','super_test', [objects, objects1])
    #res = driver.download_object_as_stream(objects)
    #print res.next()
    #print driver.delete_object(objects)
    res = driver.download_object(objects,'/root/',overwrite_existing=True)
    #container_select = Container(name='hbcloud', extra=None, driver=driver)
    #with open('/root/my_hbcloud/setup.py','rb') as iterator:
    #    res = driver.upload_object_via_stream(iter(iterator),
    #            containers,'setup.py')
    #pprint(res)
    #res = driver.copy_object('hbcloud','copy.py','hbcloud','setup.py')
    print res
