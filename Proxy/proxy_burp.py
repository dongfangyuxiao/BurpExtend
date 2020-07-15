#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2019/12/18 17:49
# @Author  : xiaodong
# @github  : https://github.com/dongfangyuxiao/
# @Site    : #
# @File    : proxy_burp.py
# @Software: PyCharm
#这是8080的burp用的，用于筛选什么流量应该转发
import threading
import re
from burp import IBurpExtender
from burp import IHttpListener
from burp import IHttpRequestResponse
from burp import IResponseInfo
from burp import IRequestInfo
from burp import IHttpService
from burp import IScannerCheck
from burp import IScannerInsertionPointProvider
from burp import IParameter
from burp import IScanIssue
from java.net import URL
from urlparse import urlparse  #我自己的环境是py3，但bp只支持py2，这里没有导入没关系的
import sys
sys.path.append('C:/Python27/Lib/site-packages')
import requests
import random
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # 屏蔽ssl警告
import socket
import json
import threading
class BurpExtender(IBurpExtender, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.registerScannerCheck(self)
        self._callbacks.setExtensionName("burp_burp")
        print("for burp_burp")
        self.lfiD = []

        self.proxiesburp = {
            "http": "http://127.0.0.1:9090",
            "https": "https://127.0.0.1:9090"
        }


        self.proxiesxray = {
            "http": "http://118.190.206.232:9093",
            "https": "https://118.190.206.232:9093"
        }

        self.proxiesAppscan = {
            "http": "http://127.0.0.1:9093",
            "https": "https://127.0.0.1:9093"
        }
        self.urls =[]


    def doPassiveScan(self, baseRequestResponse):
        Request = baseRequestResponse.getRequest()
        Response = baseRequestResponse.getResponse()
        analyzedRequest, reqHeaders, reqBodys, reqMethod, reqParameters = self.get_request_info(Request)
        ResHeaders, ResBodys, ResStatusCode, resLength = self.get_response_info(Response)
        httpService = baseRequestResponse.getHttpService()
        host, port, protocol, ishttps, = self.get_server_info(httpService)

        heaers = {
        }

        scan_target = []
        targetHost = []
        f = open('host.txt','rb')
        for line in f.readlines():
            targetHost.append(line.decode("utf-8").strip())

        host1 = ".".join(host.split('.')[1:])
        host2 = ".".join(host.split('.')[2:])
        #print targetHost
        blackdomain = [ 'img.meituan.net', 'img.meituan.net', 'p1.meituan.net', 'report.meituan.com']
        blackFile = ['js', 'css', 'jpg', 'png', 'gif', 'ico', 'woff2', 'timestamp', 'ttf', 'mp4', 'svg', 'woff']
        if (host.split('.')[-1].isdigit() or  (host1 in targetHost ) or (host2 in targetHost))and  host not in blackdomain:
            newReqUrl = self.get_request_url(protocol, reqHeaders,host,port)


            newHeaders = reqHeaders[2:]

            for header in newHeaders:

                heaers[header.split(':')[0]] = ":".join(header.split(':')[1:]).replace(" ","")
            ip = self.random_ip(host)
            #print heaers
            heaers['X-Forwarded-For'] = ip
            heaers['X-Real-IP'] = ip
            heaers['X-Forwarded-Host'] = ip
            heaers['X-Client-IP'] = ip
            heaers['X-remote-IP'] = ip
            heaers['X-remote-addr'] = ip
            heaers['True-Client-IP'] = ip
            heaers['Client-IP'] = ip
            heaers['Cf-Connecting-Ip'] = ip



            newHeaders2 = reqHeaders[2:]
            newHeaders = [str(i) for i in newHeaders2]


            tmpurl = newReqUrl.split('?')[0]
            #print tmpurl

            if str(tmpurl).endswith(tuple(blackFile)):
                pass
            else:
                print newReqUrl
                self.saveUrl(newReqUrl)

                bupscan=threading.Thread(target=self.burpscan,args=(reqMethod, newReqUrl, heaers, reqBodys))
                xrscan = threading.Thread(target=self.xray,args=(reqMethod, newReqUrl, heaers, ResBodys))
                appscan = threading.Thread(target=self.appscan,args=(reqMethod, newReqUrl, heaers, ResBodys))
                scan_target.append(bupscan)
                scan_target.append(xrscan)
                scan_target.append(appscan)

        for x in scan_target:
            x.start()
        for x in scan_target:
            x.join()






    def consolidateDuplicateIssues(self, existingIssue, newIssue):

        return 0

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        # report the issue
        return None

    def burpscan(self,reqMethod,newReqUrl,heaers,ResBodys):
        #print  "appscan get"+newReqUrl
        try:
            if reqMethod == "GET":
                response = requests.get( newReqUrl, headers=heaers, proxies=self.proxiesburp,
                                            verify=False, allow_redirects=True, timeout=15)
            else:

                response = requests.request(reqMethod,newReqUrl, headers=heaers, proxies=self.proxiesburp, data=ResBodys,
                                     verify=False, allow_redirects=True, timeout=15)
        except Exception as e:
            print e
            pass

    def xray(self, reqMethod, newReqUrl, heaers, ResBodys):
        # print "xray get"+newReqUrl

        try:
            if reqMethod == "GET":
                response = requests.get(newReqUrl, headers=heaers, proxies=self.proxiesxray, verify=False,
                                        allow_redirects=True)
            else:
                response = requests.request(reqMethod, newReqUrl, headers=heaers, proxies=self.proxiesxray,
                                            data=ResBodys,
                                            verify=False,
                                            allow_redirects=True)

        except Exception as e:
            print e
            pass

    def appscan(self, reqMethod, newReqUrl, heaers, ResBodys):
        # print  "appscan get"+newReqUrl
        try:
            if reqMethod == "GET":
                response = requests.get(newReqUrl, headers=heaers, proxies=self.proxiesAppscan,
                                        verify=False, allow_redirects=True, timeout=5)
            else:

                response = requests.request(reqMethod, newReqUrl, headers=heaers, proxies=self.proxiesAppscan,
                                            data=ResBodys,
                                            verify=False, allow_redirects=True, timeout=5)
        except Exception as e:
            print e
            pass




    def get_server_info(self, httpService):
        host = httpService.getHost()
        port = httpService.getPort()
        protocol = httpService.getProtocol()
        ishttps = False
        if protocol == 'https':
            ishttps = True
        return host, port, protocol, ishttps


    def get_response_info(self, response):
        analyzedResponse = self._helpers.analyzeResponse(
            response)
        resHeaders = analyzedResponse.getHeaders()
        resBodys = response[
                   analyzedResponse.getBodyOffset():].tostring()
        resStatusCode = analyzedResponse.getStatusCode()
        resLength = len(resBodys)
        return resHeaders, resBodys, resStatusCode, resLength

    def get_parameter_Name_Value_Type(self, parameter):
        parameterName = parameter.getName()
        parameterValue = parameter.getValue()
        parameterType = parameter.getType()
        return parameterName, parameterValue, parameterType


    def get_request_url(self, protocol, reqHeaders, host, port):
        link = reqHeaders[0].split(' ')[1]
        # host = reqHeaders[1].split(' ')
        if link.startswith('http'):#这种是正常形式如https://www.baidu.com
            return link
        else:
            return protocol + '://' + host + ":" + str(port) + link# 这种可能是如https://www.baidu.com:8090的形式



    def saveUrl(self, content):
        #print(content)
        f = open('burp_url.txt', 'at')
        f.writelines(content + '\t\n')
        f.close()

    def get_request_info(self, request):
        analyzedRequest = self._helpers.analyzeRequest(
            request)
        reqHeaders = analyzedRequest.getHeaders()
        reqBodys = request[analyzedRequest.getBodyOffset():].tostring()
        reqMethod = analyzedRequest.getMethod()
        reqParameters = analyzedRequest.getParameters()
        return analyzedRequest, reqHeaders, reqBodys, reqMethod, reqParameters

    def random_ip(self,host):
        try:
            ip =socket.gethostbyname(host)
        except:
            ip = host
        return ip
