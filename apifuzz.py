#!/usr/bin/python3

"""
Author : Prakash D
Email  : devarahalli 
Description : Peachfuzzer is a API fuzzig tool. It will
              1. Take OPENAPI2.0 API definition as input.
              2. Fuzzing data as a payload
              3. Authenticates and get the Access token
              4. Uses the access token and sends the fuzzpay load
              5. Monitor the Response time and response code.
"""

from prance import ResolvingParser
from peachFuzzAnalyze import AnalyzeApiFailures
import pprint, ast, time
import requests
from os import listdir
from threading import Thread
from datetime import datetime
import json
import sys, time, re
import logging
import urllib3
import os


#Add the proxy info; if its needed by the env
def setProxy(pIp):
  os.environ['http_proxy']  =  pIp
  os.environ['https_proxy'] =  pIp
  os.environ['HTTP_PROXY']  =  pIp
  os.environ['HTTPS_PROXY'] =  pIp
  urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
authToken = ""
refreshToken = ""
result = []
apiAuth = ""

timeout_buffer_limit = 2
continue_api = 1
timeout_buffer = 0


def createLogFile(args):
  global error_file, result_file, timeout_api_log, filtered_file
  # composing filenames
  error_file = args.type + '_Error.log'
  result_file = args.type + '_' + args.logfile
  timeout_api_log = args.type + '_time_out_errors.log'
  filtered_file = 'filtered_' +  result_file 
  

def check_and_delete_files(files):
    for file_location in files:
        if os.path.exists(file_location):
            os.remove(file_location)
        else:
            print(file_location, 'File does not exists')

""" 
Class loadOpenApiDef parses a valid OPENAPI2.0 API definition file and returns the dict 
Methods : 

returnAllPath
hostname
basepath
paths
"""
class loadOpenApiDef():

    def __init__(self, fname):
        self.parser = ResolvingParser(fname)

    def hostname(self):
        return self.parser.specification['host']

    def basepath(self):
        return self.parser.specification['basePath']

    def testData(self):
        result = []
        apiPath = list(self.parser.specification['paths'].keys())
        for i in apiPath:
            self.parser.specification['paths'][i]
            for v in list(self.parser.specification['paths'][i].keys()):
                try:
                    pn = list(self.parser.specification['paths'][i][v]['parameters'][0]['schema']['properties'].keys())
                    result.append((i, v, {'params_body': pn}))
                except IndexError as ie:
                    if len(self.parser.specification['paths'][i][v]['parameters']) == 0:
                        result.append((i, v, {'params_empty': ''}))
                        pass
                except Exception as Err:
                    pn = []
                    for ix in range(len(self.parser.specification['paths'][i][v]['parameters'])):
                        pn.append(self.parser.specification['paths'][i][v]['parameters'][ix]['name'])

                    result.append((i, v, {'params_url': pn}))
        return result


""" 
Authentication class takes care of the retriving the Authentication token and refreshing the tokens.
Methods : 

getToken
getAuthToken
getRefreshToken
renewToken
isTokenValid 
"""


class Authenticate():
    def __init__(self, url, uname, password):
        self.url = url
        self.uname = uname
        self.password = password
        self.TIMEOUT = 10

    def __loginSucessOrNot(self):
        if self.response.json()['status']['status_code'] == "SUCCESS":
            return (True, self.response.json()['uat']['access_token'], self.response.json()['rt']['refresh_token'])

        return (False, None, None)

    def getToken(self):
        self.response = requests.post(self.url, data={'email_id': self.uname, 'password': self.password}, verify=False,
                                      timeout=self.TIMEOUT)
        self.auth_status = self.__loginSucessOrNot()
        if self.auth_status[0]:
            print("INFO: Good login sucessful, Time: ", datetime.now().strftime('%Y-%m-%d %H:%M:%S'), self.auth_status)
        else:
            print("INFO: Login failed", self.response.json())

        return self.auth_status

    def getAuthToken(self):
        return self.auth_status[1]

    def getRefreshToken(self):
        return self.auth_status[2]

    def renewToken(self, rurl):
        global authToken, refreshToken
        header = {}
        header['Authorization'] = authToken
        try:
            self.response = requests.post(rurl, headers=header, data={'refresh_token': refreshToken}, verify=False,
                                          timeout=self.TIMEOUT)
            self.auth_status = self.__loginSucessOrNot()
        except Exception as ERR:
            print(ERR)

        print(self.response.json())
        print(self.response.url)
        if self.auth_status[0]:
            print("INFO: Good session refersh is sucessful ", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        else:
            print("INFO: Session refresh failed ", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

        authToken, refershToken = self.auth_status[1], self.auth_status[2]
        print("INFO: New auth Tokens auth = %s  refreshToken =%s  Time=%s" % (
            authToken, refreshToken, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        return (self.auth_status[1], self.auth_status[2])


class fuzzApi():
    def __init__(self, fuzzpayload='all'):
        self.fuzzpayload = fuzzpayload
        #    self.testlist = {'all-attacks':'fuzzpayload/fuzzdb/all-attacks',  'email':'fuzzpayload/fuzzdb/email',  \
        #                     'disclosure-localpaths':'fuzzpayload/fuzzdb/disclosure-localpaths',  \
        #                     'disclosure-directory':'fuzzpayload/fuzzdb/disclosure-directory',  'control-chars':'fuzzpayload/fuzzdb/control-chars',  \
        #                     'business-logic':'fuzzpayload/fuzzdb/business-logic',  'os-dir-indexing':'fuzzpayload/fuzzdb/os-dir-indexing',  \
        #                     'no-sql-injection':'fuzzpayload/fuzzdb/no-sql-injection',  'mimetypes':'fuzzpayload/fuzzdb/mimetypes',  'json':'fuzzpayload/fuzzdb/json',  \
        #                     'ip':'fuzzpayload/fuzzdb/ip',  'integer-overflow':'fuzzpayload/fuzzdb/integer-overflow',  'html_js_fuzz':'fuzzpayload/fuzzdb/html_js_fuzz', \
        #                     'format-strings':'fuzzpayload/fuzzdb/format-strings',  'xml':'fuzzpayload/fuzzdb/xml',  'string-expansion':'fuzzpayload/fuzzdb/string-expansion',  \
        #                     'sql-injection':'fuzzpayload/fuzzdb/sql-injection',  'server-side-include':'fuzzpayload/fuzzdb/server-side-include',  'xss':'fuzzpayload/fuzzdb/xss', \
        #                     'lfi':'fuzzpayload/fuzzdb/lfi',  'disclosure-source':'fuzzpayload/fuzzdb/disclosure-source',  'http-protocol':'fuzzpayload/fuzzdb/http-protocol',  \
        #                     'unicode':'fuzzpayload/fuzzdb/unicode',  'path-traversal':'fuzzpayload/fuzzdb/path-traversal',  'ldap':'fuzzpayload/fuzzdb/ldap',  \
        #                     'xpath':'fuzzpayload/fuzzdb/xpath',  'rfi':'fuzzpayload/fuzzdb/rfi',  'redirect':'fuzzpayload/fuzzdb/redirect',  \
        #                     'file-upload':'fuzzpayload/fuzzdb/file-upload',  'os-cmd-execution':'fuzzpayload/fuzzdb/os-cmd-execution' }

        self.testlist = {'all-attacks': 'fuzzpayload/fuzzdb/all-attacks'}

    def returnFuzzPayload(self):
        self.result = []
        testList = self.testlist
        testList = {'all-attacks': 'fuzzpayload/fuzzdb/all-attacks'}
        for dl in list(testList.values()):
            for fl in listdir(dl):
                with open(dl + '/' + fl) as f:
                    flst = f.read().splitlines()
                for payload in flst:
                    self.result.append(payload)
        return self.result


def prep_pl(dtl, fuzzpl):
    global authToken, refreshToken

    key, val = list(dtl[2].keys()), list(dtl[2].values())[0]
    header, params, data = {}, {}, {}
    if key[0] == "params_body":
        for e in val:
            data[e] = fuzzpl

    if key[0] == "params_url":
        for e in val:
            params[e] = fuzzpl

    header['authorization'] = authToken
    return (header, params, data)


def printResponseReport(r, api, payload, verb):
    global result
    res = {}
    try:
        res['status_code'] = r.status_code
        res['method'] = verb
        res['rtt'] = r.elapsed.total_seconds()
        res['api'] = r.url
        res['payload'] = payload[2]
        res['response'] = r.json()['status']['status_code']
        res['description'] = r.json()['status']['status_description']
        res['raw_response'] = r.text
        res['time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        result.append(res)
    except Exception as ERR:
        print(ERR)

    return res


def logtimeout(timeout_exception, api, payload, method):
    global timeout_buffer, continue_api, timeout_buffer_limit, timeout_api_log
    timeout_buffer -= 1
    if timeout_buffer <= 0:
        # skip_to_next_api and also log this api in the timeout logs
        continue_api = 0
        timeout_buffer = timeout_buffer_limit
        with open(timeout_api_log, 'w+') as timeout_file:
            timeout_file.write(api + ":" + method)


def sendRecvApiReq(verb):
    TIMEOUT = 10
    global timeout_buffer, timeout_buffer_limit

    def sendRecvGet(api, payload):
        try:
            r = requests.get(api, headers=payload[0], params=payload[1], data=payload[2], verify=False, timeout=TIMEOUT)
            x = printResponseReport(r, api, payload, 'get')
            print(x)
            timeout_buffer = timeout_buffer_limit
        except requests.exceptions.Timeout as timeout_exception:
            print("Error %s while sending API %s with pay load %s using method %s" % (
            timeout_exception, api, payload, verb))
            logtimeout(timeout_exception, api, payload, 'get')
        except Exception as ERR:
            print("Error %s while sending API %s with pay load %s using method %s" % (ERR, api, payload, verb))

    def sendRecvPost(api, payload):
        try:
            r = requests.post(api, headers=payload[0], params=payload[1], data=payload[2], verify=False,
                              timeout=TIMEOUT)
            x = printResponseReport(r, api, payload, 'post')
            print(x)
            # print r.json()
            timeout_buffer = timeout_buffer_limit
        except requests.exceptions.Timeout as timeout_exception:
            print("Error %s while sending API %s with pay load %s using method %s" % (
            timeout_exception, api, payload, verb))
            logtimeout(timeout_exception, api, payload, 'post')
        except Exception as ERR:
            print("Error %s while sending API %s with pay load %s using method %s" % (ERR, api, payload, verb))

    def sendRecvDelete(api, payload):
        try:
            r = requests.delete(api, headers=payload[0], params=payload[1], data=payload[2], verify=False,
                                timeout=TIMEOUT)
            x = printResponseReport(r, api, payload, 'delete')
            print(x)
            timeout_buffer = timeout_buffer_limit
        except requests.exceptions.Timeout as timeout_exception:
            print("Error %s while sending API %s with pay load %s using method %s" % (
            timeout_exception, api, payload, verb))
            logtimeout(timeout_exception, api, payload, 'delete')
        except Exception as ERR:
            print("Error %s while sending API %s with pay load %s using method %s" % (ERR, api, payload, verb))

    def sendRecvPatch(api, payload):
        try:
            r = requests.patch(api, headers=payload[0], params=payload[1], data=payload[2], verify=False,
                               timeout=TIMEOUT)
            x = printResponseReport(r, api, payload, 'patch')
            print(x)
            timeout_buffer = timeout_buffer_limit
        except requests.exceptions.Timeout as timeout_exception:
            print("Error %s while sending API %s with pay load %s using method %s" % (
            timeout_exception, api, payload, verb))
            logtimeout(timeout_exception, api, payload, 'patch')
        except Exception as ERR:
            print("Error %s while sending API %s with pay load %s using method %s" % (ERR, api, payload, verb))

    def sendRecvPut(api, payload):
        try:
            r = requests.put(api, headers=payload[0], params=payload[1], data=payload[2], verify=False, timeout=TIMEOUT)
            x = printResponseReport(r, api, payload, 'put')
            print(x)
            timeout_buffer = timeout_buffer_limit
        except requests.exceptions.Timeout as timeout_exception:
            print("Error %s while sending API %s with pay load %s using method %s" % (
            timeout_exception, api, payload, verb))
            logtimeout(timeout_exception, api, payload, 'put')
        except Exception as ERR:
            print("Error %s while sending API %s with pay load %s using method %s" % (ERR, api, payload, verb))

    funcdict = {'get': sendRecvGet, 'post': sendRecvPost, 'delete': sendRecvDelete, 'patch': sendRecvPatch,
                'put': sendRecvPut}
    return funcdict[verb]


def startFuzz(args, baseurl, testData, fuzzPayload):
    global result, continue_api, timeout_buffer_limit, timeout_buffer, result_file
    result = []
    print(args.pattern)

    for tda in testData:
        timeout_buffer = timeout_buffer_limit
        if not re.search(args.pattern, tda[0]) and (args.pattern is not None):
            continue
        for fpl in fuzzPayload:
            api = baseurl + tda[0]
            method = tda[1]
            payload = prep_pl(tda, fpl)
            # print "Sending API %s with pay load %s using method %s" % ( api, payload, method)
            if (continue_api == 1):
                runFunc = sendRecvApiReq(method)
                runFunc(api, payload)
            else:
                continue_api = 1
                break

        with open(result_file, "w+") as write_file:
            json.dump(result, write_file)


def refreshhelperFunc(apiObj):
    pass
    #Incase your API implements the refresh token functionality enhance this function.


def logFilter(input_file, filtered_file):
  fRes = []
  with open(input_file, 'r') as fd :
      jd = json.load(fd)

  for ln in jd :
      if AnalyzeApiFailures.statusCodeCheck(ln, 500):
        fRes.append(ln)

      if AnalyzeApiFailures.descCodeCheck(ln, "SERVICE_UNAVAILABLE"):
        fRes.append(ln)

      if AnalyzeApiFailures.descCodeCheck(ln, "INTERNAL_ERROR"):
        fRes.append(ln)

      if AnalyzeApiFailures.responseTimeValidation(ln, 3 ):
        fRes.append(ln)

  with open(filtered_file,'w') as f:
    json.dump(fRes,f )

