import os
import time

from pprint import pprint
from ConfigParser import ConfigParser
from libcloud.storage.base import Container, Object
from libcloud.storage.types import Provider
from libcloud.storage.providers import get_driver

CONF_FILE_PATH = '/root/SDSCloud/etc/cloud_basic.conf'
DEFAULT_PATH = '/root/test/'

def transform_cloud_name(name):
    """
    Transform cloud name in Configuration files to libcloud Provider.
    e.g. 'Ali OSS' ---- 'ali_oss'
    """
    cloud_name = name.strip()
    if ' ' in cloud_name:
        cloud_name = cloud_name.replace(' ','_',1)
        cloud_name = cloud_name.replace(' ','')
    return cloud_name.lower()

def get_keys_from_conf(path):
    keys_dict = {}
    cloud_conf = ConfigParser()
    cloud_conf.read(path)
    for section in cloud_conf.sections():
        if not section.startswith('cloud:'):
            continue
        cloud_name = transform_cloud_name(section[6:])
        accesskeyid = cloud_conf.get(section, 'accesskeyid')
        accesskeysecret = cloud_conf.get(section, 'accesskeysecret')
        keys_dict[cloud_name] = [accesskeyid, accesskeysecret]
    return keys_dict

def nine_func_test(cloud_name, test_container='kunworld', test_obj='objfile'):
    keys_dict = get_keys_from_conf(CONF_FILE_PATH)
    accesskeyid, accesskeysecret = keys_dict[cloud_name]
    CloudDriver = get_driver(cloud_name)
    driver = CloudDriver(accesskeyid, accesskeysecret)
    #driver.delete_container(Container(test_container,None,None))
    prin = lambda x: "="*30 + x + "TEST" +"="*30
    print prin(cloud_name)
    print "."*100
    print "."*100

    print 30*"-" + "list containers" + 30*"-"
    containers = driver.list_containers()
    pprint(containers)
    print 70*"-"

    print 30*"-" + "put container" + 30*"-"
    created_container = driver.create_container(test_container)
    print " "*10 + "Container %s CREATE success" % created_container.name
    print 70*"-"

    print 30*"-" + "get container" + 30*"-"
    got_container = driver.get_container(test_container)
    print " "*10 + "Container %s GET success!" % got_container.name
    print 70*"-"

    print 30*"-" + "normal put object" + 30*"-"
    filepath = DEFAULT_PATH + 'uploadfile'
    put_obj = driver.upload_object(filepath, created_container, test_obj)
    print " "*10 + "Object %s in Container %s upload success!" % (
            put_obj.name, put_obj.container.name)
    print 70*"-"

    print 30*"-" + "normal get object" + 30*"-"
    get_obj = driver.download_object(put_obj, DEFAULT_PATH,
            overwrite_existing=True)
    get_file_path = DEFAULT_PATH + put_obj.name
    print " "*10 + "%s download success, size %d!" % (get_file_path,
            os.path.getsize(get_file_path))
    print 70*"-"

    print 30*"-" + "delete object" + 30*"-"
    delete_flag = driver.delete_object(put_obj)
    if delete_flag:
        print "%s DELETE success!" % put_obj.name
    else:
        print "%s DELETE failed!" % put_obj.name
    print 70*"-"
    os.remove(get_file_path)

    print 30*"-" + "put object as stream" + 30*"-"
    streampath = DEFAULT_PATH + 'streamfile'
    start_time = time.time()
    put_obj_stream = driver.upload_object_via_stream(open(streampath, "r"),
            created_container, test_obj)
    time_cost = time.time() - start_time
    print " "*10 + "Object %s in Container %s upload as stream success!" % (
            put_obj_stream.name, put_obj_stream.container.name)
    print "Time cost %.5f" % time_cost
    print 70*"-"

    print 30*"-" + "get object as stream" + 30*"-"
    start_time = time.time()
    get_obj_stream = driver.download_object_as_stream(put_obj_stream)
    stream_download_path = DEFAULT_PATH + "stream_download"
    with open(stream_download_path, 'w') as fp:
        for item in get_obj_stream:
            fp.write(item)
        fp.flush()
    cost_time = time.time() - start_time
    print " "*10 + "%s download success, size %d!" % (streampath,
            os.path.getsize(stream_download_path))
    print "Time cost %.5f" % cost_time
    print 70*"-"

    os.remove(stream_download_path)
    driver.delete_object(put_obj_stream)

    print 30*"-" + "delete container" + 30*"-"
    delete_container_flag = driver.delete_container(created_container)
    if delete_container_flag:
        print "%s DELETE container success!" % created_container.name
    else:
        print "%s DELETE container fail!" % created_container.name
    print 70*"-"

    print "."*100
    print "."*100
    print "*"*50 + "  END  " + "*"*50


if __name__ == "__main__":
    nine_func_test("ali_oss")
