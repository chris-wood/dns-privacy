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
        if packet.query != None:
            if packet.query.name not in domains:
                print >> sys.stderr, "%d,%s" % (num, packet.query.name)
                num += 1
            
            name = packet.query.name
            domains.add(name)
            runner.push(len(name))

for dirpath, dnames, fnames in os.walk(sys.argv[1]):
    for f in fnames:
        if f.endswith(".pcap.gz"):
            print >> sys.stderr, "Opening %s" % (f)
            with gzip.open(os.path.join(dirpath, f), 'rb') as fh:
                process_pcap(fh)
        elif f.endswith(".pcap"):
            process_pcap(open(os.path.join(dirpath, f), "r"))

        print runner.all()
        print >> sys.stderr, runner.all()

with open(sys.argv[2], "w") as fh:
    for domain in domains:
        fh.write(str(domain) + "\n")
