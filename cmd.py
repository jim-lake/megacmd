
import os
import array
import sys
import time
import datetime
import json
import httplib
import urlparse
import random
import base64
from Crypto.Cipher import AES
from Crypto.Util import Counter

__SSL_FILE_XFER__ = True


#test url: https://mega.co.nz/#!ckgAHYwb!HJ76cRzzAJZRALOj-EwyrzZv31QXyGZpMfzcNMsFaNE

__CS_URL__ = "https://eu.api.mega.co.nz/cs"

__CBC_IV__ = "\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00"

__POST_HEADERS__ = {
    'User-Agent': 'megacmd/0.01',
    'Accept': '*/*',
    'Content-Type': 'application/json',
}

g_seq_num = random.randrange(1,1000000)

class jsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.strftime("%a, %d %b %Y %H:%M:%S GMT")
        else:
            return json.JSONEncoder.default(self, obj)

def dumps(obj):
    return json.dumps(obj,cls=jsonEncoder)

def get_conn():
    return httplib.HTTPSConnection(__HOST__)
#return httplib.HTTPConnection('127.0.0.1',9000)

def rest_post(url,data):
    url_parts = urlparse.urlparse(url)
    conn = httplib.HTTPSConnection(url_parts.hostname)
    uri = "%s?%s" % (url_parts.path,url_parts.query)
    
    #print "uri: %r" % uri
    
    conn.request('POST',uri,data,__POST_HEADERS__)
    #print "sent request"
    response = conn.getresponse()
    #print "got response: %s" % response.status
    data = None
    if response.status == 200:
        data = response.read()
        #print "data: %r" % data
    
    return (response.status,data)

def get_file(url):
    #print "get_file: %r" % url
    url_parts = urlparse.urlparse(url)
    if url_parts.scheme == 'https':
        conn = httplib.HTTPSConnection(url_parts.hostname)
    else:
        conn = httplib.HTTPConnection(url_parts.hostname)
    uri = "%s" % url_parts.path
    if len(url_parts.query) > 0:
        uri += "?%s" % url_parts.query
    #print "get_file: uri: %r" % uri
    conn.request('GET',uri)
    response = conn.getresponse()
    #print "got response: %s" % response.status
    data = None
    if response.status == 200:
        data = response.read()
        #print "data: len: %d" % len(data)
    
    return (response.status,data)


def mega_get():
    global g_seq_num

    if len(sys.argv) < 3:
        print "megacmd: Get requires URL parameter"
        exit()

    url = sys.argv[2]
    print "Doing get on Mega URL: %s" % url

    parts = urlparse.urlparse(url)

    #print "Fragment: %s" % parts.fragment
    #print "host: %s" % parts.hostname
    #print "scheme: %s" % parts.scheme

    file_key = parts.fragment.split('!')

    file = file_key[1]
    key = file_key[2]

    #print "File: %r" % file
    #print "Key(%d): %r" % (len(key),key)

    cmd = {
        "a": "g",
        "g": 1,
        "p": file,
        "ssl": 0,
        }

    if __SSL_FILE_XFER__:
        cmd['ssl'] = 1

    cmd_array = [cmd]

    post_body = json.dumps(cmd_array)

    #print "json: %s" % post_body

    seq_num = g_seq_num
    g_seq_num += 1

    url = "%s?id=%s" % (__CS_URL__,seq_num)

    #print "url: %s" % url

    (status,response) = rest_post(url,post_body)
    #print "status: %s" % status
    #print "response: %s" % response
    
    if status != 200:
        print "megacmd: Failed to find file data, please check URL."
        exit()

    rest_json = json.loads(response)

    #print "rest_json: %r" % rest_json

    file_url = rest_json[0]['g']
    at = rest_json[0]['at'].encode('utf8')
    #at = "LeyTaT74W0ECa_9J2HdlgZZErn2g-IZhdN1N0WUsaFg"

    #print "at(%d): %r" % (len(at),at)

    key_decoded = base64.b64decode(key + "=","-_")

    #print "key_decoded(%dbits): %s" % (len(key_decoded)*8,key_decoded.encode("hex"))

    aes_key_array = array.array('B', key_decoded[0:16])
    key2 = array.array('B', key_decoded[16:32])

    for i in range(len(aes_key_array)):
        aes_key_array[i] ^= key2[i]

    aes_key = aes_key_array.tostring()
    #print "aes_key(%dbits): %s" % (len(aes_key)*8,aes_key.encode("hex"))

    decryptor = AES.new(aes_key, AES.MODE_CBC, __CBC_IV__)

    at_decoded = base64.b64decode(at + "=","-_")
    #print "at_decoded(%dbits): %s" % (len(at_decoded)*8,at_decoded.encode("hex"))

    decrypted_at = decryptor.decrypt(at_decoded)

    #print "decrypted_at(%dbits): %s : %s" % (len(decrypted_at)*8,decrypted_at.encode("hex"),decrypted_at)

    if not decrypted_at.startswith("MEGA"):
        print "megacmd: Attribute block did not start with MEGA.  Please check your encryption key."
        exit()

    file_json = decrypted_at[4:].strip("\00")
    #print "file_json: %r" % file_json
    file_attributes = json.loads(file_json)

    #print "file_attributes: %r" % file_attributes

    file_name = file_attributes['n']

    #print "file_name: %r" % file_name

    (status,file_data) = get_file(file_url)

    ctr_prefix = key_decoded[16:24]
    #print "ctr_prefix(%dbits): %s" % (len(ctr_prefix)*8,ctr_prefix.encode("hex"))

    ctr = Counter.new(64,initial_value=0,prefix=ctr_prefix)

    decryptor = AES.new(aes_key, AES.MODE_CTR, counter=ctr)
    decrypted_file_data = decryptor.decrypt(file_data)

    #print "decrypted_file_data(%d): %s : %r" % (len(decrypted_file_data),decrypted_file_data.encode("hex"),decrypted_file_data)

    i = 0
    base_file_name = file_name
    while True:
        #print "checking file: %s" % file_name
    
        if not os.path.exists(file_name):
            break
        i += 1
        file_name = "%s.%d" % (base_file_name,i)

    print "Writing to file: %s" % file_name

    f = open(file_name,"wb")
    f.write(decrypted_file_data)
    f.close()

    print "Done writing."


def usage():
    print "Mega Command Line Util v0.01"
    print "megacmd <cmd> [args]"
    print ""
    print "Commands: get"
    print ""

if __name__ == '__main__':
    
    if len(sys.argv) < 2:
        usage()
        exit()

    cmd = sys.argv[1]

    if cmd == 'get':
        mega_get()
    else:
        print "megacmd: Unknown command: %s" % cmd
        exit()
    
    print "done done"

