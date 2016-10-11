import sys
import os
import gzip

from pcap_parser import *
from stats import *

domains = set()
num = 0
runner = RunningStat()

def process_pcap(fh):
    global domains
    global num
    global runner

    parser = PacketParser()
    packets = parser.parseDNS(fh)
    for packet in packets:
        if packet.dns.qr == 1:
            val = len(packet.ethernetPacket.data)
            print val
            runner.push(val)

for dirpath, dnames, fnames in os.walk(sys.argv[1]):
    for f in fnames:
        if f.endswith(".pcap.gz"):
            print >> sys.stderr, "Opening %s" % (f)
            with gzip.open(os.path.join(dirpath, f), 'r') as fh:
                process_pcap(fh)
        elif f.endswith(".pcap"):
            with open(os.path.join(dirpath, f), "r") as fh:
                process_pcap(fh)
        print >> sys.stderr, runner.all()

#for domain in domains:
#    print str(domain)
