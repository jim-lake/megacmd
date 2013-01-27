
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

#test url: https://mega.co.nz/#!1pZykQpJ!K4rX2EIZ1sb2FeTXXz43-hl4RQIIhw3pyp7yhnWj_uo

__CS_URL__ = "https://eu.api.mega.co.nz/cs"
#__CS_URL__ = "https://research-services.boingo.com/reflect.php"

__CBC_IV__ = "\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00"

__POST_HEADERS__ = {
    'User-Agent': 'megacmd/0.01',
    'Accept': '*/*',
    #'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
#    'Accept-Encoding': '',
    #'Accept-Language': 'en-US,en;q=0.8',
    #'Cache-Control': 'no-cache',
    #'Connection': 'keep-alive',
    'Content-Type': 'application/json',
    #'Origin': 'https://mega.co.nz',
    #'Pragma': 'no-cache',
    #'Referer': 'https://mega.co.nz/',
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

def write_data(post_body):
    conn = get_conn()
    conn.request('POST','/internal/external_refresh',post_body,__POST_HEADERS__)
    response = conn.getresponse()
    data = response.read()
    print "post response: %r: %s" % (response.status,data)
    return data

def rest_post(url,data):
    url_parts = urlparse.urlparse(url)
    conn = httplib.HTTPSConnection(url_parts.hostname)
    print "got conn"
    uri = "%s?%s" % (url_parts.path,url_parts.query)
    
    print "uri: %s" % uri
    
    conn.request('POST',uri,data,__POST_HEADERS__)
    print "sent request"
    response = conn.getresponse()
    print "got response: %s" % response.status
    data = None
    if response.status == 200:
        data = response.read()
        print "data: %r" % data
    
    return (response.status,data)

def mega_get():
    global g_seq_num

    if len(sys.argv) < 3:
        print "mega_cmd: Get requires URL parameter"
        exit()

    url = sys.argv[2]
    print "Doing get on Mega URL: %s" % url

    parts = urlparse.urlparse(url)

    print "Fragment: %s" % parts.fragment
    print "host: %s" % parts.hostname
    print "scheme: %s" % parts.scheme

    file_key = parts.fragment.split('!')

    file = file_key[1]
    key = file_key[2]

    print "File: %r" % file
    print "Key(%d): %r" % (len(key),key)

    cmd = {
        "a": "g",
        "g": 1,
        "p": file,
        "ssl": 0,
        }
    cmd_array = [cmd]

    post_body = json.dumps(cmd_array)

    print "json: %s" % post_body

    seq_num = g_seq_num
    g_seq_num += 1

    url = "%s?id=%s" % (__CS_URL__,seq_num)

    print "url: %s" % url

    #(status,response) = rest_post(url,post_body)
    #print "status: %s" % status
    #print "response: %s" % response

    at = "LeyTaT74W0ECa_9J2HdlgZZErn2g-IZhdN1N0WUsaFg"

    print "at(%d): %r" % (len(at),at)

    key_decoded = base64.b64decode(key + "=","-_")

    print "key_decoded(%dbits): %s" % (len(key_decoded)*8,key_decoded.encode("hex"))

    aes_key_array = array.array('B', key_decoded[0:16])
    key2 = array.array('B', key_decoded[16:32])

    for i in range(len(aes_key_array)):
        aes_key_array[i] ^= key2[i]

    aes_key = aes_key_array.tostring()
    print "aes_key(%dbits): %s" % (len(aes_key)*8,aes_key.encode("hex"))

    decryptor = AES.new(aes_key, AES.MODE_CBC, __CBC_IV__)

    at_decoded = base64.b64decode(at + "=","-_")
    print "at_decoded(%dbits): %s : %s" % (len(at_decoded)*8,at_decoded.encode("hex"),at_decoded)

    decrypted_at = decryptor.decrypt(at_decoded)

    print "decrypted_at(%dbits): %s : %s" % (len(decrypted_at)*8,decrypted_at.encode("hex"),decrypted_at)

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
        print "mega_cmd: Unknown command: %s" % cmd
        exit()
    
    print "done done"