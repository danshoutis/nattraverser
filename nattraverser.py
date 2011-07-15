#!/usr/bin/env python

from pystun.stun import get_nat_type
import pyzenity.PyZenity as zdlg
import select, os
import socket
import struct

try: import simplejson as json
except ImportError: import json as json
import random

def get_stun(source_ip="0.0.0.0", source_port=54321):
    socket.setdefaulttimeout(2)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind((source_ip, source_port))
    nat_type, nat = get_nat_type(s, source_ip, source_port)
    print("DEBUG...:")
    print(repr(nat_type))
    print(repr(nat))
    return nat,nat_type

class PeerConnection(object):
    # constant messages:
    HELO = "nattraverser.py v.0"
    HELO_TIME = 1.0 # every 1 second...
    BUFSZ = 1500

    def __init__(self, 
                 sock, 
                 peeraddr, 
                 progf, 
                 known_helo = None, 
                 known_pid = None):
        self.a = peeraddr
        self.sock = sock
        self.startwait()
        self.helo_ids = {}
        self.peer_helo_ids = {}
        self.progf = progf

    def send(self, what):
        self.sock.sendto(what, self.a)
        
    # Rendezvous initiation protocol: 
    #  Continuously send a 'HELO' message of (helo_id, peer_helo_id).
    #  Initially, peer_helo_id is None; helo_id is fresh each time.
    #  Upon reciving a peer hello (msg) w/ msg.peer_helo_id of None, set
    #    peer_helo_id to the recived value.
    #  Upon reciving a peer hello (msg) with msg.peer_helo_id in self.helo_ids,
    #    Return the (now fixed) helo_id and peer_helo_id.
    def send_helo(self, heloid,peerid):
        if heloid is None:
            heloid = random.randint(1,20000000)
            self.helo_ids[heloid] = heloid
        payload = json.dumps( [heloid,peerid] )
        message = HELO + payload
        self.send(message)

    def read_helo(self):
        r,o = self.sock.recvfrom(1500)
        if (o != self.peeraddr):
            print("Packet from a non-peer.")
            return None
        if r.startswith(PeerConnection.HELO):
            payload = r[len(PeerConnection.HELO):]
            heloid,pid = json.loads(payload)
            
            return (heloid,self.helo_ids.get(pid,None))
        else:
            print("Not a HELO.")
            return None,None

    def start(self):
        known_peer_id = None
        known_helo_id = None
        try: while 1:
            # Try listening for one second:
            readable,_,errored = select.select([self.sock], [], [self.sock], Peer.HELO_TIME)
            if (len(errored) > 0): raise "Socket error?"
            if (len(readable) == 0):
                self.send_helo(known_helo_id, known_peer_id)
                continue

            known_peer_id, known_helo_id = read_helo()
            if (known_peer_id is not None and
                    known_helo_id is not None):
                return (known_helo_id, known_peer_id)
                
                
        except KeyboardInterrupr: print"Stopped by user during setup."

    # Talk protocol:
    #  Three types of packets:
    #  1. general packets
    #  2. 'helo'/'keepalive' packets
    #  3. general packets that had to be escaped because of unfortunate 
    #     resemblance to #2, or, being meta, #3.
    def talk_out_packet(self, p):
        
    

def forward_packets(f, peer):
    try:
        while 1:
            r = select.select([f, peer.sock])[0][0]
            if (r == in_f):
                peer.send(os.read(f,1500))
            else:
                buf,p = s.recvfrom(1500)
                if (p != peer):
                    print("Bad peer packet: %s:%i vs %s:%i" % (p+peer_addr))
                    os.write(f, buf)
    except KeyboardInterrupt:
        print "Stopped by user."

def allocate_tun(

def main(tcp_port=23,localconnect=True):
    nat, nat_type = get_stun()
    

if __name__ == "__main__":
    get_stun()

