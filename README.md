# tcpscan

一个用python3写的端口扫描小脚本,主要数用socket和telnetlib,支持开放服务探测,输出为json格式。
### help

    Tcp PortScan V1.0 
    optional arguments:

    -h, --help            show this help message and exit
    -i IP, --ip IP        Scan an ip or cidr list eg. 1.1.1.1 or 1.1.1.0/24
    -d DOMAIN, --domain DOMAIN
                        Scan a domain name eg. -d www.google.com
    -f FILE, --file FILE  Read the ip list from the file
    -p PORT, --port PORT  Set scan port 21,22,23..., default scan 350+ port
    -m METHOD, --method METHOD
                        Tcp or telnet scan, tcp calls socket and identifies
                        service
    -t THREAD, --thread THREAD
                        set threads, default:200
                        

### usage
    tcpscan.py -i 1.1.1.1
    tcpscan.py -i 1.1.1.1 -p 22,80,445
    tcpscan.py -i 1.1.1.0/24 -m tcp -t 200
    tcpscan.py -f ip.txt -m tcp -t 200
    tcpscan.py -d google.com

### output
    {
    "ip": "192.168.1.1",
    "port": 9050,
    "proto": "http",
    "payload": "b'HTTP/1.1 200 OK\\r\\nX-DNS-Prefetch-Control: off\\r\\nX-Frame-Options: SAMEORIGIN\\r\\nStrict-Transport-Security: max-age=15552000; includeSubDomains\\r\\nX-Download-Options: noopen\\r\\nX-Content-Type-Options: nosniff\\r\\nX-XSS-Protection: 1; mode=block\\r\\nContent-Type: application/json; charset=utf-8\\r\\nContent-Length: 15\\r\\nETag: W/\"f-KOwe7l9ASePE8hNQacHSyA\"\\r\\nDate: Thu, 31 Jan 2019 08:23:33 GMT\\r\\nConnection: keep-alive\\r\\n\\r\\n{\"status\":true}'"
    }
    {
    "ip": "192.168.1.1",
    "port": 8088,
    "proto": "http",
    "payload": "b'HTTP/1.1 200 OK\\r\\nVary: Cookie\\r\\nContent-Type: text/html; charset=utf-8\\r\\nContent-Language: en\\r\\n\\r\\n<!doctype html>\\n<html>\\n  <head>\\n    <meta charset=\"utf-8\">\\n    <!-- <meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\"> -->\\n    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\\n    <title>Virtualization Station</title>\\n    <link rel=\"shortcut icon\" href=\"static/favicon.ico\">\\n    <link rel=\"stylesheet\" href=\"static/common.css?v=3.1.834\">\\n    <link rel=\"stylesheet\" href=\"static/login.css?v=3.1.'"
    }
    {
    "ip": "192.168.1.1",
    "port": 9051,
    "proto": "http",
    "payload": "b'HTTP/1.1 200 OK\\r\\nX-Powered-By: Express\\r\\nContent-Type: application/json; charset=utf-8\\r\\nContent-Length: 15\\r\\nETag: W/\"f-KOwe7l9ASePE8hNQacHSyA\"\\r\\nDate: Thu, 31 Jan 2019 08:23:33 GMT\\r\\nConnection: keep-alive\\r\\n\\r\\n{\"status\":true}'"
    }
