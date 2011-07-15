#!/usr/bin/env python

from pystun.stun import get_nat_type
import pyzenity.PyZenity as zdlg
import select, os, sys, time
import socket
import struct
import fcntl
import subprocess

try: import simplejson as json
except ImportError: import json as json
import random

class PeerConnection(object):
    # constant messages
    # Randomly chosen by fair dice roll.
    SPECIAL = "!41cc9b1c5559617f31f97d6f10eec1e4" 
    HELO = SPECIAL + " nattraverser.py v.0"
    ESC = SPECIAL + ":esc:"
    HELO_TIME = 1.0 # every 1 second...
    BUFSZ = 1500

    def __init__(self, 
                 sock, 
                 progf,
                 peeraddr,
                 tunnel_fd = None,
                 known_helo = None, 
                 known_pid = None):
        if (isinstance(sock,int)):
            sock = socket.fromfd(sock, socket.AF_INET, socket.SOCK_DGRAM)

        self.peeraddr = peeraddr
        self.sock = sock
        self.helo_ids = {}
        self.peer_helo_ids = {}
        self.progf = progf
        self.tunnel_fd = tunnel_fd
        self.known_helo = known_helo
        self.known_pid = known_pid
        self.peer_adj = False
        self.written = 0
        self.read = 0

    def send(self, what):
        self.sock.sendto(what, self.peeraddr)
        
    # Rendezvous initiation protocol: 
    #  Continuously send a 'HELO' message of (helo_id, peer_helo_id).
    #  Initially, peer_helo_id is None; helo_id is fresh each time.
    #  Upon reciving a peer hello (msg) w/ msg.peer_helo_id of None, set
    #    peer_helo_id to the recived value.
    #  Upon reciving a peer hello (msg) with msg.peer_helo_id in self.helo_ids,
    #    Return the (now fixed) helo_id and peer_helo_id.
    def send_helo(self, heloid,peerid):
        print("Sending helo")
        self.send(self.make_helo(heloid,peerid))
    def make_helo(self, heloid, peerid):
        if heloid is None:
            heloid = random.randint(1,20000000)
            self.helo_ids[heloid] = heloid
        payload = json.dumps( [heloid,peerid] )
        return PeerConnection.HELO + payload


    def read_helo(self):
        r,o = self.sock.recvfrom(1500)

        if not self.peer_adj:
            ip,port = o
            peerip,oport = self.peeraddr
            if (ip == peerip):
                self.peeraddr = (peerip,port)
                self.peer_adj = True

        if (o != self.peeraddr):
            print("Packet from a non-peer.")
            return None,None

        if r.startswith(PeerConnection.HELO):
            payload = r[len(PeerConnection.HELO):]
            heloid,pid = json.loads(payload)
            
            return (heloid,self.helo_ids.get(pid,None))
        else:
            print("Not a HELO: %s" % r)
            return None,None

    def start(self):
        known_peer_id = None
        known_helo_id = None
        prog = 5
        count = 1
        peer = "%s:%d" % self.peeraddr
        try: 
            while 1:
                # Try listening for one second:
                readable,_,errored = select.select([self.sock], [], [self.sock], PeerConnection.HELO_TIME)
                if (len(errored) > 0): raise "Socket error?"
                if (len(readable) == 0):
                    self.progf(prog, "Connecting %s (%d)" % (peer,count))
                    count += 1
                    self.send_helo(known_helo_id, known_peer_id)
                    continue
                
                known_peer_id, known_helo_id = self.read_helo()
                prog = 10
                if (known_peer_id is not None and
                    known_helo_id is not None):
                    prog = 15
                    self.progf(prog,"Connected.")
                    return (known_helo_id, known_peer_id)
                
        except KeyboardInterrupt: 
            print"Stopped by user during setup."
            return None, None

    # Talk protocol:
    #  Three types of packets:
    #  1. general packets
    #  2. extra 'helo' packets
    #  3. general packets that had to be escaped because of unfortunate 
    #     resemblance to #2 (or #3).
    def talk_out_packet(self, p):
        self.written += len(p)
        if (p.startswith(PeerConnection.SPECIAL)):
            p = PeerConnection.ESC + p
        self.send(p)

    def talk_in_packet(self):
        p,peer = self.sock.recvfrom(1500)

        # TODO: should come from cmdline.
        if peer != self.peeraddr:
            print("WARNING: packet from a non-peer address.")
            return None



        if (p.startswith(PeerConnection.ESC)):
            return p[len(PeerConnection.ESC):]

        elif (p.startswith(PeerConnection.HELO)):
            # ignore.
            print("Keepalive/helo")
            return None
        else:
            return p

    # The actual tunneling:
    def talk(self):
        assert(self.tunnel_fd is not None)
        assert(self.tunnel_fd is not None)
        last_prog = time.time()
        fds = [ self.tunnel_fd, self.sock.fileno() ]
        self.progf(100, "Connected (in:%d, out:%d)" % (self.read, self.written))
        while 1:
            readable,_,_ = select.select(fds,[],[],PeerConnection.HELO_TIME)
            if (len(readable) > 0):
                if readable[0] == self.tunnel_fd:
                    self.talk_out_packet(os.read(self.tunnel_fd, 1500))
                else:
                    w  = self.talk_in_packet()
                    if (w is not None):
                        self.read += len(w)
                        os.write(self.tunnel_fd, w)

            # Continue to send HELO messages if we haven't read/written
            #  anything recently.
            t = time.time()
            diff = t - last_prog

            if (diff >= PeerConnection.HELO_TIME):
                self.send_helo(self.known_helo, self.known_pid)
                last_prog = t
                self.progf(100, "Connected (in:%d, out:%d)" % (self.read, self.written))

def get_stun(source_ip="0.0.0.0", source_port=54321):
    #socket.setdefaulttimeout(2)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind((source_ip, source_port))
    nat_type, nat = get_nat_type(s, source_ip, source_port)
    return nat,nat_type

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002

def allocate_tun():
    f = os.open("/dev/net/tun", os.O_RDWR)
    ifs = fcntl.ioctl(f, TUNSETIFF, struct.pack("16sH", "toto%d", IFF_TUN))
    ifname = ifs[:16].strip("\x00")
    return (ifname,f)

def configure_tun(ifname, local_addr, remote_addr):

    #print("Upping: %r" % repr(["ifconfig", ifname, "netmask", "255.255.255.254", local_addr]))
    #subprocess.Popen(["ifconfig", ifname, "netmask", "255.255.255.254", local_addr]).wait()
    args = ["ifconfig",
            ifname,
            local_addr,
            "pointopoint",
            remote_addr]
    print("Configuring iface: %r" % args)
    assert(0 == subprocess.Popen(args).wait())
    print("Configured.")

    rargs = ["route",
             "add",
             "-host",
             remote_addr,
             ifname ]
    print("Configuring route: %r" % rargs)
    assert(0 == subprocess.Popen(rargs).wait())
    print("Route up?")


def main_usermode(tcp_port=23,localconnect=True):
    prog, prog_fin, _ = zdlg.Progress("Creating the magic cookie.", pulsate=True)
    
    public_port = random.randint(9000,56421)
    nat, nat_type = get_stun("0.0.0.0", public_port)
    print(repr(nat))
    local_addr = [ 10, 15, 11, random.randint(1,254) ]

    winner = random.random()
    cookie = "!!" + json.dumps({ "ip" : nat["ExternalIP"],
                                 "port" : nat["ExternalPort"], 
                                 "winner" : winner,
                                 "addr" : local_addr,
                                 "stun" : { "nat" : nat, "nt" : nat_type } }) + "!!"

    prog_fin()

    zdlg.InfoMessage("Copy the magic cookie, (everything between and including the double exclamation marks), and send it to the person you're connecting to:\n\n" + cookie + "\n")

    remote_cookie = None
    while remote_cookie is None:
        rc = zdlg.GetText("Paste the other person's magic cookie here.")
        st = rc.find("!!")
        nd = rc.rfind("!!")
        if st < 0 or nd < 0: continue
        try:
            st = st + len("!!")
            rc = rc[st:nd]
            remote_cookie = json.loads(rc)
        except: 
            print("Bad cookie?")
            print(rc)
            continue
    
    # Figure out the tunneled addresses:
    remote_wins = remote_cookie["winner"] > winner # tiebreak
    remote_addr = remote_cookie["addr"]
    mod_addr = remote_addr
    src_addr = local_addr
    if remote_wins: 
        mod_addr = local_addr
        src_addr = remote_addr
    
    mod_addr[2] = src_addr[2] 
    mod_addr[3] = src_addr[3] & 254
    if mod_addr[3] == src_addr[3]: mod_addr[3] = src_addr[3] | 1    
    
    # Start up the progress dialog:
    prog,prog_close,(pstdin,pstdout) = zdlg.Progress("Connecting.")

    udpsock = socket.socket(socket.AF_INET,
                            socket.SOCK_DGRAM)
    udpsock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    print("Binding")
    udpsock.bind(("", public_port))
    print("Bound.")

    peer = PeerConnection(udpsock, prog, (remote_cookie["ip"], remote_cookie["port"]))

    selfid,peerid = peer.start()

    # Enter superuser mode and finish:
    peer_ip,peer_port = peer.peeraddr
    cfid = max(udpsock.fileno(), pstdin) + 1
    args = map(str, [pstdin,
                     ".".join(map(str,local_addr)),
                     ".".join(map(str,remote_addr)),
                     peer_ip,
                     peer_port,
                     udpsock.fileno(),
                     selfid,
                     peerid])

    
    main_rootmode([''] + args)

    # SCRATCH
    #superusermode = subprocess.Popen(["gksudo",
    #                                  sys.executable,
    #                                  os.path.abspath(__file__)] + args)
                               
    #superusermode.wait()
    prog_close()
    udpsock.close()
    


def main_rootmode(args=sys.argv):
    print("SUPERUSER MODE: %r" % args[1:])
    progress_write = int(args[1])
    print("Could I open it up?")
    def prog(pct,msg=None):
        if (pct >= 100): pct = 99
        os.write(progress_write,"%d\n" % pct)
        if msg:
            print(msg)
            os.write(progress_write,"# %s\n" % msg)

    prog(50, "Entered superuser mode.")

    print("Progress written?")

    local_addr = args[2]
    remote_addr = args[3]
    peer_addr = args[4]
    peer_port = int(args[5])
    udp_sock_fd = int(args[6])
    known_helo = int(args[7])
    known_pid = int(args[8])

    tun_dev, tun_fd = allocate_tun()
    configure_tun(tun_dev, local_addr, remote_addr)
    peer = PeerConnection(udp_sock_fd,
                          prog,
                          (peer_addr,peer_port),
                          tun_fd,
                          known_helo,
                          known_pid)
                          
    peer.talk()

if __name__ == "__main__":
    if os.geteuid() != 0:
        p = subprocess.Popen(["gksudo", sys.executable, os.path.abspath(__file__)])
        p.wait()
    else:
        main_usermode()
    
