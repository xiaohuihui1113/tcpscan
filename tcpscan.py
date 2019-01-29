#coding:utf-8
import socket
import time
import telnetlib
import re
import ipaddress
import concurrent.futures
import sys
import argparse
import random
import os
sys.path.append(os.getcwd())

THREADNUM = 200  #线程数
METHOD = 1  # 0是调用socket扫描，1是调用telnet扫描
OPEN_PORTS = 0
OPEN_HOSTS = []
DOMAIN = False
FILE = False
SIGNS = (
    #协议 | 版本 | 关键字
    b'smb|smb|^\0\0\0.\xffSMBr\0\0\0\0.*',
    b"xmpp|xmpp|^\<\?xml version='1.0'\?\>",
    b'netbios|netbios|^\x79\x08.*BROWSE',
    b'netbios|netbios|^\x79\x08.\x00\x00\x00\x00',
    b'netbios|netbios|^\x05\x00\x0d\x03',
    b'netbios|netbios|^\x82\x00\x00\x00',
    b'netbios|netbios|\x83\x00\x00\x01\x8f',
    b'backdoor|backdoor|^500 Not Loged in',
    b'backdoor|backdoor|GET: command',
    b'backdoor|backdoor|sh: GET:',
    b'bachdoor|bachdoor|[a-z]*sh: .* command not found',
    b'backdoor|backdoor|^bash[$#]',
    b'backdoor|backdoor|^sh[$#]',
    b'backdoor|backdoor|^Microsoft Windows',
    b'db2|db2|.*SQLDB2RA',
    b'dell-openmanage|dell-openmanage|^\x4e\x00\x0d',
    b'finger|finger|^\r\n	Line	  User',
    b'finger|finger|Line	 User',
    b'finger|finger|Login name: ',
    b'finger|finger|Login.*Name.*TTY.*Idle',
    b'finger|finger|^No one logged on',
    b'finger|finger|^\r\nWelcome',
    b'finger|finger|^finger:',
    b'finger|finger|^must provide username',
    b'finger|finger|finger: GET: ',
    b'ftp|ftp|^220.*\n331',
    b'ftp|ftp|^220.*\n530',
    b'ftp|ftp|^220.*FTP',
    b'ftp|ftp|^220 .* Microsoft .* FTP',
    b'ftp|ftp|^220 Inactivity timer',
    b'ftp|ftp|^220 .* UserGate',
    b'ftp|ftp|^220.*FileZilla Server',
    b'ldap|ldap|^\x30\x0c\x02\x01\x01\x61',
    b'ldap|ldap|^\x30\x32\x02\x01',
    b'ldap|ldap|^\x30\x33\x02\x01',
    b'ldap|ldap|^\x30\x38\x02\x01',
    b'ldap|ldap|^\x30\x84',
    b'ldap|ldap|^\x30\x45',
    b'ldp|ldp|^\x00\x01\x00.*?\r\n\r\n$',
    b'rdp|rdp|^\x03\x00\x00\x0b',
    b'rdp|rdp|^\x03\x00\x00\x11',
    b'rdp|rdp|^\x03\0\0\x0b\x06\xd0\0\0\x12.\0$',
    b'rdp|rdp|^\x03\0\0\x17\x08\x02\0\0Z~\0\x0b\x05\x05@\x06\0\x08\x91J\0\x02X$',
    b'rdp|rdp|^\x03\0\0\x11\x08\x02..}\x08\x03\0\0\xdf\x14\x01\x01$',
    b'rdp|rdp|^\x03\0\0\x0b\x06\xd0\0\0\x03.\0$',
    b'rdp|rdp|^\x03\0\0\x0b\x06\xd0\0\0\0\0\0',
    b'rdp|rdp|^\x03\0\0\x0e\t\xd0\0\0\0[\x02\xa1]\0\xc0\x01\n$',
    b'rdp|rdp|^\x03\0\0\x0b\x06\xd0\0\x004\x12\0',
    b'rdp-proxy|rdp-proxy|^nmproxy: Procotol byte is not 8\n$',
    b'msrpc|msrpc|^\x05\x00\x0d\x03\x10\x00\x00\x00\x18\x00\x00\x00\x00\x00',
    b'msrpc|msrpc|\x05\0\r\x03\x10\0\0\0\x18\0\0\0....\x04\0\x01\x05\0\0\0\0$',
    b'mssql|mssql|^\x05\x6e\x00',
    b'mssql|mssql|^\x04\x01',
    b'mssql|mysql|;MSSQLSERVER;',
    b'mysql|mysql|mysql_native_password',
    b'mysql|mysql|^\x19\x00\x00\x00\x0a',
    b'mysql|mysql|^\x2c\x00\x00\x00\x0a',
    b'mysql|mysql|hhost \'',
    b'mysql|mysql|khost \'',
    b'mysql|mysql|mysqladmin',
    b'mysql|mysql|whost \'',
    b'mysql|mysql|^[.*]\x00\x00\x00\n.*?\x00',
    b'mysql-secured|mysql|this MySQL server',
    b'mysql-secured|MariaDB|MariaDB server',
    b'mysql-secured|mysql-secured|\x00\x00\x00\xffj\x04Host',
    b'db2jds|db2jds|^N\x00',
    b'nagiosd|nagiosd|Sorry, you \(.*are not among the allowed hosts...',
    b'nessus|nessus|< NTP 1.2 >\x0aUser:',
    b'oracle-tns-listener|\(ERROR_STACK=\(ERROR=\(CODE=',
    b'oracle-tns-listener|\(ADDRESS=\(PROTOCOL=',
    b'oracle-dbsnmp|^\x00\x0c\x00\x00\x04\x00\x00\x00\x00',
    b'oracle-https|^220- ora',
    b'rmi|rmi|\x00\x00\x00\x76\x49\x6e\x76\x61',
    b'rmi|rmi|^\x4e\x00\x09',
    b'postgresql|postgres|Invalid packet length',
    b'postgresql|postgres|^EFATAL',
    b'rpc-nfs|rpc-nfs|^\x02\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00',
    b'rpc|rpc|\x01\x86\xa0',
    b'rpc|rpc|\x03\x9b\x65\x42\x00\x00\x00\x01',
    b'rpc|rpc|^\x80\x00\x00',
    b'rsync|rsync|^@RSYNCD:',
    b'smux|smux|^\x41\x01\x02\x00',
    b'snmp-public|snmp-public|\x70\x75\x62\x6c\x69\x63\xa2',
    b'snmp|snmp|\x41\x01\x02',
    b'socks|socks|^\x05[\x00-\x08]\x00',
    b'ssl|ssl|^..\x04\0.\0\x02',
    b'ssl|ssl|^\x16\x03\x01..\x02...\x03\x01',
    b'ssl|ssl|^\x16\x03\0..\x02...\x03\0',
    b'ssl|ssl|SSL.*GET_CLIENT_HELLO',
    b'ssl|ssl|^-ERR .*tls_start_servertls',
    b'ssl|ssl|^\x16\x03\0\0J\x02\0\0F\x03\0',
    b'ssl|ssl|^\x16\x03\0..\x02\0\0F\x03\0',
    b'ssl|ssl|^\x15\x03\0\0\x02\x02\.*',
    b'ssl|ssl|^\x16\x03\x01..\x02...\x03\x01',
    b'ssl|ssl|^\x16\x03\0..\x02...\x03\0',
    b'sybase|sybase|^\x04\x01\x00',
    b'telnet|telnet|Telnet',
    b'telnet|telnet|^\xff[\xfa-\xff]',
    b'telnet|telnet|^\r\n%connection closed by remote host!\x00$',
    b'rlogin|rlogin|login: ',
    b'rlogin|rlogin|rlogind: ',
    b'rlogin|rlogin|^\x01\x50\x65\x72\x6d\x69\x73\x73\x69\x6f\x6e\x20\x64\x65\x6e\x69\x65\x64\x2e\x0a',
    b'tftp|tftp|^\x00[\x03\x05]\x00',
    b'uucp|uucp|^login: password: ',
    b'vnc|vnc|^RFB',
    b'imap|imap|^\* OK.*?IMAP',
    b'pop|pop|^\+OK.*?',
    b'smtp|smtp|^220.*?SMTP',
    b'smtp|smtp|^554 SMTP',
    b'ftp|ftp|^220-',
    b'ftp|ftp|^220.*?FTP',
    b'ftp|ftp|^220.*?FileZilla',
    b'ssh|ssh|^SSH-',
    b'ssh|ssh|connection refused by remote host.',
    b'rtsp|rtsp|^RTSP/',
    b'sip|sip|^SIP/',
    b'nntp|nntp|^200 NNTP',
    b'sccp|sccp|^\x01\x00\x00\x00$',
    b'webmin|webmin|.*MiniServ',
    b'webmin|webmin|^0\.0\.0\.0:.*:[0-9]',
    b'websphere-javaw|websphere-javaw|^\x15\x00\x00\x00\x02\x02\x0a',
    b'smb|smb|^\x83\x00\x00\x01\x8f',
    b'mongodb|mongodb|MongoDB',
    b'rsync|rsync|@RSYNCD:',
    b'mssql|mssql|MSSQLSERVER',
    b'vmware|vmware|VMware',
    b'redis|redis|^-ERR unknown command',
    b'redis|redis|^-ERR wrong number of arguments',
    b'redis|redis|^-DENIED Redis is running',
    b'memcached|memcached|^ERROR\r\n',
    b'websocket|websocket|^HTTP.*?websocket',
    b'http|http|^HTTP',
    b'http|https|^\<!DOCTYPE HTML PUBLIC',
    b'http|topsec|^\x15\x03\x03\x00\x02\x02',
    b'svn|svn|^\( success \( 2 2 \( \) \( edit-pipeline svndiff1',
    b'dubbo|dubbo|^Unsupported command',
    b'http|elasticsearch|cluster_name.*elasticsearch',
)

port_list = [
    7, 11, 13, 15, 17, 19, 21, 22, 23, 25, 26, 37, 47, 49, 53, 69, 70, 79, 80,
    81, 82, 83, 84, 88, 102, 104, 110, 111, 113, 119, 123, 129, 135, 137, 139,
    143, 161, 175, 179, 195, 311, 389, 443, 444, 445, 465, 500, 502, 503, 512,
    513, 514, 515, 520, 523, 530, 548, 554, 563, 587, 593, 623, 626, 631, 636,
    660, 666, 749, 751, 771, 789, 873, 901, 902, 990, 992, 993, 995, 1000,
    1010, 1023, 1024, 1025, 1080, 1088, 1099, 1111, 1177, 1200, 1234, 1311,
    1400, 1433, 1434, 1471, 1515, 1521, 1599, 1604, 1723, 1741, 1777, 1883,
    1900, 1911, 1962, 1991, 2000, 2049, 2067, 2081, 2082, 2083, 2086, 2087,
    2123, 2152, 2181, 2222, 2323, 2332, 2333, 2375, 2376, 2379, 2404, 2455,
    2480, 2601, 2604, 2628, 3000, 3001, 3128, 3260, 3269, 3283, 3299, 3306,
    3310, 3311, 3312, 3333, 3386, 3388, 3389, 3460, 3478, 3493, 3541, 3542,
    3689, 3690, 3702, 3749, 3780, 3784, 3790, 4000, 4022, 4040, 4063, 4064,
    4070, 4200, 4343, 4369, 4440, 4443, 4444, 4500, 4567, 4664, 4730, 4782,
    4786, 4800, 4840, 4848, 4911, 4949, 5000, 5001, 5006, 5007, 5008, 5009,
    5060, 5094, 5222, 5269, 5353, 5357, 5431, 5432, 5433, 5555, 5560, 5577,
    5601, 5632, 5672, 5683, 5800, 5801, 5858, 5900, 5901, 5938, 5984, 5985,
    5986, 6000, 6001, 6082, 6379, 6664, 6666, 6667, 6881, 6969, 7000, 7001,
    7002, 7071, 7218, 7474, 7547, 7548, 7549, 7657, 7777, 7779, 8000, 8001,
    8008, 8009, 8010, 8060, 8069, 8080, 8081, 8083, 8086, 8087, 8088, 8089,
    8090, 8098, 8099, 8112, 8126, 8139, 8140, 8181, 8191, 8200, 8307, 8333,
    8334, 8443, 8554, 8649, 8800, 8834, 8880, 8883, 8888, 8889, 8899, 9000,
    9001, 9002, 9009, 9042, 9050, 9051, 9080, 9090, 9092, 9100, 9151, 9160,
    9191, 9200, 9300, 9306, 9418, 9443, 9595, 9600, 9869, 9943, 9944, 9981,
    9998, 9999, 10000, 10001, 10243, 10554, 11211, 11300, 12345, 13579, 14147,
    16010, 16992, 16993, 17000, 18081, 18245, 20000, 20547, 21025, 21379,
    21546, 22022, 23023, 23424, 23389, 25105, 25565, 27015, 27016, 27017,
    27018, 27019, 28015, 28017, 30000, 30718, 32400, 32764, 32768, 32769,
    32770, 32771, 33389, 33890, 33899, 37777, 44818, 47808, 48899, 49152,
    49153, 50000, 50030, 50050, 50070, 50100, 51106, 53413, 54138, 55443,
    55553, 55554, 62078, 64738, 65535
]


def ReadFile(file):
    with open(file, 'rt') as f:
        ips = f.readlines()
        for i in ips:
            start = ScanPort(i.strip(), METHOD, THREADNUM).run()


class ScanPort():
    def __init__(self, ipaddr, METHOD, THREADNUM):
        self.THREADNUM = THREADNUM
        self.ipaddr = ipaddr
        self.method = METHOD

    def SockPort(self, hosts):
        global OPEN_PORTS, OPEN_HOSTS, SIGNS
        socket.setdefaulttimeout(1)
        ip = hosts[0]
        port = hosts[1]
        response1 = b''
        proto = 'Unknow'
        payload = 'X' * int(random.random() * 100)
        payload1 = ('GET / HTTP/1.1\r\nHOST: %s\r\n\r\n' % ip)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((ip, port))
            if result == 0:
                OPEN_HOSTS.append(ip)
                OPEN_PORTS += 1
                sock.sendall(payload1.encode())
                response1 = sock.recv(256)
                for pattern in SIGNS:
                    pattern = pattern.split(b'|')
                    if re.search(pattern[-1], response1, re.IGNORECASE):
                        proto = pattern[1].decode()
                        break
                sys.stdout.write("%s\t%s\t%s\n" % (ip, port, proto))

        except:
            raise
        finally:
            sock.close()

    def TelnetScan(self, hosts):
        global OPEN_PORTS, OPEN_HOSTS
        ip = hosts[0]
        port = hosts[1]
        try:
            tn = telnetlib.Telnet(ip, port, timeout=1)
            sys.stdout.write("%s\t%s\n" % (ip, port))
            OPEN_PORTS += 1
            OPEN_HOSTS.append(ip)
        except:
            pass

    def Scan(self, ip):
        hosts = []
        global port_list
        for i in port_list:
            hosts.append([str(ip), i])
        # print(len(hosts))
        try:
            with concurrent.futures.ThreadPoolExecutor(
                    max_workers=self.THREADNUM) as executor:
                if self.method == 0:
                    executor.map(self.SockPort, hosts)
                else:
                    executor.map(self.TelnetScan, hosts)
        except EOFError:
            pass

    def run(self):
        global DOMAIN
        if DOMAIN == True:
            ipaddr = [socket.gethostbyname(self.ipaddr)]
        elif re.search('/', self.ipaddr):
            ipaddr = list(ipaddress.ip_network(self.ipaddr).hosts())
        else:
            ipaddr = [self.ipaddr]
        try:
            with concurrent.futures.ThreadPoolExecutor(
                    max_workers=10) as executor:
                executor.map(self.Scan, ipaddr)
        except EOFError:
            pass


if __name__ == '__main__':
    start_time = time.time()
    parser = argparse.ArgumentParser(description='Tcp PortScan V1.0')
    parser.add_argument(
        "-i", "--ip", help='Scan an ip or cidr list eg. 1.1.1.1 or 1.1.1.0/24')
    parser.add_argument(
        "-d", "--domain", help='Scan a domain name eg. -d www.google.com')
    parser.add_argument('-f', '--file', help='Read the ip list from the file')
    parser.add_argument(
        "-p",
        "--port",
        help='Set scan port 21,22,23..., default scan 350+ port')
    parser.add_argument(
        '-m',
        '--method',
        help='Tcp or telnet scan, tcp calls socket and identifies service')
    parser.add_argument("-t", "--thread", help='set threads, default:200')
    args = parser.parse_args()
    if args.method == 'tcp':
        METHOD = 0
    elif args.method == 'telnet':
        METHOD == 1
    if type(args.thread) == 'int' and args.thread > 0:
        THREADNUM = args.thread
    if args.port:
        port_list = args.port.split(',')
    if args.file:
        ReadFile(args.file)
    if args.domain:
        DOMAIN = True
        start = ScanPort(args.domain, METHOD, THREADNUM).run()
    if args.ip:
        start = ScanPort(args.ip, METHOD, THREADNUM).run()
    end_time = time.time()
    print('\nTotal host:\t{}'.format(len(set(OPEN_HOSTS))))
    print('Total port:\t{}'.format(OPEN_PORTS))
    print('running {0:.3f} seconds...'.format(end_time - start_time))
