import sys
import os
import gzip

from pcap_parser import *

domains = set()
num = 0

for dirpath, dnames, fnames in os.walk(sys.argv[1]):
    for f in fnames:
        if f.endswith(".pcap.gz"):
            print >> sys.stderr, "Opening %s" % (f)
            with gzip.open(os.path.join(dirpath, f), 'rb') as fh:
            # with open(os.path.join(dirpath, f), 'rb') as fh:
                parser = PacketParser()
                packets = parser.parseDNS(fh)
                for packet in packets:
                    if packet.query != None:
                        if packet.query.name not in domains:
                            print "%d,%s" % (num, packet.query.name)
                            num += 1
                        domains.add(packet.query.name)

print len(domains)
with open(sys.argv[2], "w") as fh:
    for domain in domains:
        fh.write(str(domain) + "\n")
