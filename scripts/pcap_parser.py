import sys
import traceback
import dpkt
import ipaddress
import socket

class ResourceRecord(object):
    def __init__(self, ip, rr):
        self.ip = ip
        self.rr = rr
        self.srcAddress = socket.inet_ntoa(ip.src)
        self.dstAddress = socket.inet_ntoa(ip.dst)
        self.targetAddress = None
        self._unpack()

    def _unpack(self):
        self.target = self.rr.name
        self.type = self.rr.type

        # Parse the RR type (see https://en.wikipedia.org/wiki/List_of_DNS_record_types)
        if self.rr.type == 5:
            self.cname = self.rr.cname
        elif self.rr.type == 1:
            self.targetAddress = socket.inet_ntoa(self.rr.rdata)
        elif self.rr.type == 12:
            self.ptrname = self.rr.ptrname

class Query(object):
    def __init__(self, ip, dns, query):
        self.ip = ip
        self.query = query
        self.dns = dns
        self.srcAddress = socket.inet_ntoa(ip.src)
        self.dstAddress = socket.inet_ntoa(ip.dst)
        self._unpack()

    def split(self, string):
        return str(self.name).split(string)

    def _unpack(self):
        self.name = self.query.name
        self.id = self.dns.id
        self.qr = self.dns.qr
        self.type = self.query.type

class DNSPacket(object):
    def __init__(self, index, ethernetPacket, ts):
        self.ethernetPacket = ethernetPacket
        self.query = None
        self.records = []
        self.ts = ts
        self.index = index
        self.isDNS = self.unpack()

    def unpack(self, debug = False):
        validPacket = False
        ipv4 = True

        print dpkt.ethernet.ETH_TYPE_IP
        print dpkt.ethernet.ETH_TYPE_IP6
        print self.ethernetPacket.type
        print repr(self.ethernetPacket)
        if self.ethernetPacket.type == dpkt.ethernet.ETH_TYPE_IP:
            validPacket = True
        if self.ethernetPacket.type == dpkt.ethernet.ETH_TYPE_IP6:
            validPacket = True
            ipv4 = False

        if not validPacket:
            return False

        self.ip = self.ethernetPacket.data
        if (ipv4 and self.ip.p == dpkt.ip.IP_PROTO_UDP) or (not ipv4 and self.ip.nxt == dpkt.ip.IP_PROTO_UDP):
            print "ok"
            self.udp = self.ip.data

            tb = None
            try:
                self.dns = dpkt.dns.DNS(self.udp.data)

                # QR = 0, query
                # QR = 1, response
                if self.dns.qr == 0:
                    self.query = Query(self.ip, self.dns, self.dns.qd[0])
                    self.src = self.query.srcAddress
                    self.dst = self.query.dstAddress
                else:
                    for rr in self.dns.an:
                        self.records.append(ResourceRecord(self.ip, rr))
                    self.src = self.records[0].srcAddress
                    self.dst = self.records[0].dstAddress
                return True
            except Exception as e:
                isDns = False
                tb = traceback.format_exc()
                if debug:
                    print >> sys.stderr, str(e)
            finally:
                if tb != None and debug:
                    print tb
        else:
            return False

class PacketParser(object):
    def __init__(self):
        pass

    def parseDNS(self, handle):
        pcapFile = dpkt.pcap.Reader(handle)

        dnsPackets = []
        index = 0
        # gzip = dpkt.gzip.Gzip()
        for ts, pkt in pcapFile:
            try:
                # gzip = dpkt.gzip.Gzip(pkt)
                # raw_buffer = gzip.unpack(pkt)
                eth = dpkt.ethernet.Ethernet(pkt)
                # gzip = dpkt.gzip.Gzip()
                # gzip.unpack(eth)

                print eth
                packet = DNSPacket(index, eth, ts)
                if packet.isDNS:
                    dnsPackets.append(packet)
            except Exception as e:
                raise
            index = index + 1

        return dnsPackets
