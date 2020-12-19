#! /usr/bin/env python
#pcap comes with multiple sessions or connections, this short program helps in splitting single pcap to multiple.
import logging
import argparse
import os,sys

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
pkts = PacketList()

def read_pcap(file):
	global pkts
	pkts = rdpcap(file)

def split_pcap(file):
	for stream in extract_streams(file):
		stream_pkts = PacketList()
		sip, sport, dip, dport = stream.split(':')
		print '*'*5+sport,dport+'*'*5
		for pkt in pkts:
			if pkt.haslayer(IP) and pkt.haslayer(TCP):
				if ((pkt[IP].dst == sip) or (pkt[IP].src) == sip) and ((pkt[IP].dst == dip) or (pkt[IP].src == dip)):
					if ((pkt[IP].sport == int(dport)) or (pkt[IP].sport) == int(sport)) and ((pkt[IP].dport == int(sport)) or (pkt[IP].dport == int(dport))):
						stream_pkts.append(pkt)
			else:
				pass
		name = sip+'_'+sport+'->'+dip+'_'+dport+'.pcap'.replace('/','_')
		if len(stream_pkts) > 0:
			wrpcap(name,stream_pkts)

def parse_session(session):
	netflow = session.replace('UDP ','').replace('TCP ','').replace(' > ',':')
	netflow = netflow.split(':')
	netflow = ":".join(netflow)
	return netflow

def extract_streams(file):
	netflow = []
	for session in pkts.sessions():
		try:
			sip, sport, dip, dport = parse_session(session).split(':')
			flow = [sip+':'+sport+':'+dip+':'+dport ,dip+':'+dport+':'+sip+':'+sport]
			if not ((flow[0] in netflow) or (flow[1] in netflow)) :
				netflow.append(flow[0])
		except:
			pass
	return netflow

if __name__ == "__main__":
	if len(sys.argv) > 1:
		if os.path.isfile(sys.argv[1]):
				read_pcap(sys.argv[1])
				split_pcap(sys.argv[1])
		else:
			print 'required valid pcap file'
	else:
		print 'require pcap file as parameter'
