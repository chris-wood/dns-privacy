import sys
import os
import gzip

from pcap_parser import *
from stats import *

import subprocess

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
            print >> sys.stderr, name, len(name)

for dirpath, dnames, fnames in os.walk(sys.argv[1]):
    for f in fnames:
        filename = os.path.join(dirpath, f)
        if f.endswith(".pcap.gz"):
            print >> sys.stderr, "Opening %s" % (f)
            #subprocess.Popen(['gunzip', filename])

            with gzip.open(filename, 'rb') as fh:
                process_pcap(fh)
        elif f.endswith(".pcap"):
            process_pcap(open(filename, "r"))

        print >> sys.stderr, runner.all()

for domain in domains:
    print str(domain)
