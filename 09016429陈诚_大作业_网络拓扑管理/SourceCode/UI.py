#coding:utf-8
import tkinter
import socket
import struct
import time
import select
import Traceroute_ICMP as traceroute
import csv
import networkx as nx
import matplotlib
matplotlib.use('TkAgg')
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import matplotlib.pyplot as plt

#初始化Tk
root = tkinter.Tk()
root.title("网络拓扑管理工具")
root.geometry('600x400')
#框架布局
frame1 = tkinter.Frame(root)  
frame2 = tkinter.Frame(root)  
frame3 = tkinter.Frame(root)
frame4 = tkinter.Frame(root)
#框架的位置布局
frame1.pack(side=tkinter.TOP)
frame2.pack(side=tkinter.TOP)
frame3.pack(side=tkinter.TOP)
frame4.pack(side=tkinter.TOP)
#frame1
tkinter.Label(frame1, text="请输入一个互联网地址以跟踪路径。", font=("Arial", 14)).pack(side=tkinter.TOP)
var = tkinter.Variable()
entry = tkinter.Entry(frame1, textvariable=var)
var.set("")
entry.pack(side=tkinter.LEFT)
tkinter.Label(frame1, text="（例如，10.0.2.1 或 www.example.com）", font=("Arial", 12)).pack(side=tkinter.LEFT)
#frame3
scroll = tkinter.Scrollbar()
text = tkinter.Text(frame3, bg='grey')
scroll.config(command=text.yview) #将文本框关联到滚动条上
text.config(yscrollcommand=scroll.set) #将滚动条关联到文本框
scroll.pack(side=tkinter.RIGHT,fill=tkinter.Y)
text.pack(side=tkinter.LEFT,fill=tkinter.Y)
#frame4
f = plt.Figure(figsize=(5,4), dpi=100) 
canvas = FigureCanvasTkAgg(f, master=frame4)
canvas.get_tk_widget().pack(side=tkinter.TOP, fill=tkinter.BOTH, expand=1)
canvas.draw()
#frame2
global IProute
IProute = []

def tracert():
    text.delete(0.0,tkinter.END)
    text.insert(tkinter.END,'Start tracing route, please wait...\n')
    text.update()
    hostname = entry.get()
    myAddr = socket.gethostbyname(socket.getfqdn(socket.gethostname()))
    destAddr = socket.gethostbyname(str(hostname))
    global IProute
    IProute = []
    IProute.append(myAddr)
    text.insert(tkinter.END,"Traceroute to %s (IP:%s)\n"%(str(hostname),destAddr))
    text.insert(tkinter.END,"Protocol: ICMP, %d hops max\n"%(traceroute.MAX_HOPS))
    text.insert(tkinter.END,"sourceAddr: %s\n"%myAddr)
    text.update()
    timeLeft = traceroute.TIMEOUT
    for ttl in range(1,traceroute.MAX_HOPS):
        for _ in range(traceroute.TRIES):
            
            icmp = socket.getprotobyname("icmp")
            mySocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, icmp)
            mySocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(traceroute.TIMEOUT)
            try:
                d = traceroute.build_packet()
                mySocket.sendto(d, (str(hostname), 0))
                t = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)

                if whatReady[0] == []: # Timeout
                    text.insert (tkinter.END,"*    *    * Request timed out.\n")
                    text.update()

                recvPacket, addr = mySocket.recvfrom(1024)
                #text.insert (addr)
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect

                if timeLeft <= 0:
                    timeLeft = 0
                    text.insert (tkinter.END,"*    *    * Request timed out.\n")
                    text.update()

            except socket.timeout:
                continue

            else:
                icmpHeader = recvPacket[20:28]
                request_type, _, _, _, _ = struct.unpack("bbHHh", icmpHeader)

                if request_type == 11:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    text.insert (tkinter.END," %d   rtt=%.0fms, ip: %s\n" % (ttl,(timeReceived -t)*1000, addr[0]))
                    text.update()
                    IProute.append(addr[0])
                    break
                elif request_type == 3:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    text.insert (tkinter.END," %d   rtt=%.0fms, ip: %s\n" % (ttl,(timeReceived -t)*1000, addr[0]))
                    text.update()
                    IProute.append(addr[0])
                    break
                elif request_type == 0:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    text.insert (tkinter.END," %d   rtt=%.0fms, ip: %s\n" % (ttl,(timeReceived -timeSent)*1000, addr[0]))
                    text.insert(tkinter.END,'Traceroute over.\n')
                    text.update()
                    IProute.append(addr[0])

                    return
                else:
                    text.insert (tkinter.END,"ERROR!\n")
                    text.update()
                    break
            finally:
                mySocket.close()

def save():
    global IProute
    text.insert(tkinter.END,'Start saving...\n')
    text.update()
    IPs = []
    nodefile='node.csv'
    edgefile='edge.csv'
    if IProute is None:
        text.insert(tkinter.END,'ERROR in saving!\n')
        text.update()
        return

    nodefileReader = open(nodefile, 'a', encoding='utf-8')
    if nodefileReader is not None:
        text.insert(tkinter.END,'node file opened.\n')
        text.update()
    for i in range(len(IProute)):
        if IProute[i] in IPs:
            continue
        else:
            IPs.append(IProute[i])
        if IProute[i].startswith('10.'):
            nodefileReader.write(IProute[i]+','+'0'+'\n')
        else:
            nodefileReader.write(IProute[i]+','+'1'+'\n')

    edgefileReader = open(edgefile, 'a', encoding='utf-8')
    if edgefileReader is not None:
        text.insert(tkinter.END,'edge file opened.\n')
        text.update()
    for i in range(len(IProute)-1):
        edgefileReader.write(IProute[i]+','+IProute[i+1]+'\n')

    nodefileReader.close()
    edgefileReader.close()

    text.insert(tkinter.END,'...saved\n')
    text.update()

    return

def draw():
    text.insert(tkinter.END,'showing network graph!\nGreen node represents extranet ip\nRed node represents intranet ip')
    nodeList = []
    nodecolorTag = []
    edgeList = []
    nodecolor = []

    csvfile = open('node.csv','r')
    csv_reader_rows = csv.reader(csvfile)
    for one_line in csv_reader_rows:
        nodeList.append(one_line[0])
        nodecolorTag.append(one_line[1])
    #print(nodeList)
    #print(nodecolorTag)
    csvfile.close()

    csv_file = open('edge.csv','r')
    csv_reader_lines = csv.reader(csv_file)
    for one_line in csv_reader_lines:
        edgeList.append(one_line)
    csv_file.close()

    G = nx.Graph()
    G.add_nodes_from(nodeList)
    G.add_edges_from(edgeList)
    for node in G.nodes():
        if node.startswith('10.'):
            nodecolor.append('r')
        else:
            nodecolor.append('g')
    
    nx.draw_networkx(G, pos=nx.fruchterman_reingold_layout(G), node_color=nodecolor, with_labels=False, node_size=100, font_size=6)
    #f.draw(nx.draw(G, pos=nx.spring_layout(G), node_color=nodecolor, with_labels=True, font_size=6))
    plt.show()
    canvas.draw()

tkinter.Button(frame2, text="Traceroute", command=tracert, bd = 6).pack(side=tkinter.LEFT)
tkinter.Button(frame2, text="保存路由路径", command=save, bd = 6).pack(side=tkinter.LEFT)
tkinter.Button(frame2, text="显示网络拓扑图", command=draw, bd = 6).pack(side=tkinter.LEFT)

root.mainloop()