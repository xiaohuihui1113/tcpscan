# tcpscan

一个用python3写的端口扫描小脚本，主要数用socket和telnetlib，支持开放服务探测。
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
