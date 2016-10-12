#!/usr/bin/env python

import sys
import math
import statistics
from stats import *
import argparse
import networkx as nx
from pcap_parser import *

import random

###

def query(packets):
    hits = {}
    for (t, p) in packets:
        if t not in hits:
            hits[t] = [p]
        else:
            hits[t].append(p)
    return hits

def query_random_walk(G, rtt, packets):
    hits = {}
    max_t = 0
    min_t = 2 ** 32
    for (t, p) in packets:
        if t not in hits:
            hits[t] = [p]
        else:
            hits[t].append(p)
        if t > max_t:
            max_t = t
        if t < min_t:
            min_t = t

    start_node_idx = random.randint(0, len(G.nodes()))
    start_node = G.nodes()[start_node_idx]
    curr_t = min_t
    while curr_t < max_t:
        percentage = random.random()
        next_hop = rtt * percentage

        if start_node not in hits:
            hits[curr_t] = [start_node]
        else:
            hits[curr_t].append(start_node)

        # go to the next guy...
        neighbors = G.neighbors(start_node)
        if len(neighbors) == 0:
            start_node_idx = random.randint(0, len(G.nodes()) - 1)
            start_node = G.nodes()[start_node_idx]
        else:
            start_node_idx = random.randint(0, len(neighbors) - 1)
            start_node = neighbors[start_node_idx]

        curr_t += next_hop
        # print curr_t, max_t


    return hits

def main(args):
    parser = PacketParser()

    dnsPackets = []
    for filename in args.file:
        fh = open(filename, 'r')
        packets = parser.parseDNS(fh)
        domains = []
        for packet in packets:
            dnsPackets.append(packet)

    averageRTT = RunningStat()

    G = nx.DiGraph()
    query_name_map = {}

    for i, p1 in enumerate(dnsPackets):
        if p1.query != None and (p1.ts, p1.query.name) not in domains:
            domains.append((p1.ts, p1.query.name))
        for j, p2 in enumerate(dnsPackets):
            if i < j:
                if p1.query != None and p2.query != None:
                    if p1.query.name not in query_name_map:
                        query_name_map[p1.query.name] = len(query_name_map)
                    if p2.query.name not in query_name_map:
                        query_name_map[p2.query.name] = len(query_name_map)

                    if p1.query.srcAddress == p2.query.srcAddress:
                        if p1.ts < p2.ts:
                            G.add_edge(p1.query.name, p2.query.name)
                        else:
                            G.add_edge(p2.query.name, p1.query.name)

                        delta = abs(p1.ts - p2.ts)
                        averageRTT.push(delta)


    hits_normal = query(domains)
    hits_chaff = query_random_walk(G, averageRTT.mean() / 2.0, domains)

    # print hits_normal
    # print "\n\n\n"
    # print hits_chaff

    normal_out = open(args.normal, "w")
    chaff_out = open(args.chaff, "w")

    min_t = min(hits_normal.keys())
    sorted_times = hits_normal.keys()
    sorted_times.sort()
    for time in sorted_times:
        for target in hits_normal[time]:
            target = query_name_map[target]
            normal_out.write(str(time - min_t) + "," + str(target) + "\n")

    sorted_times = hits_chaff.keys()
    sorted_times.sort()
    for time in sorted_times:
        for target in hits_chaff[time]:
            target = query_name_map[target]
            chaff_out.write(str(time - min_t) + "," + str(target) + "\n")


    import matplotlib.pyplot as plt

    pos = nx.spring_layout(G)
    nx.draw(G, pos, node_size=1500, node_color='yellow', font_size=8, font_weight='bold')
    labels=nx.draw_networkx_labels(G,pos)
    # plt.tight_layout()
    # plt.show()
    # plt.savefig("Graph.png", format="PNG")

if __name__ == "__main__":
    desc = '''
Build a domain relationship graph from PCAP files.
'''

    parser = argparse.ArgumentParser(prog=sys.argv[0], formatter_class=argparse.RawDescriptionHelpFormatter, description=desc)
    parser.add_argument('-f', '--file', action="store", required=True, help="Relative path to PCAP file to parse", nargs="+")
    parser.add_argument('-n', '--normal', action="store", required=True, help="Normal write file")
    parser.add_argument('-c', '--chaff', action="store", required=True, help="Chaff write file")
    # parser.add_argument('--ql', default=False, action="store_true", help="Query length feature")
    # parser.add_argument('--qr', default=False, action="store_true", help="Query resolution time feature")
    # parser.add_argument('--tn', default=False, action="store_true", help="Query target name feature")
    # parser.add_argument('--qf', action="store", help="Query frequency with parameterized window")
    # parser.add_argument('--tf', action="store", help="Source target frequency with parameterized window")
    # parser.add_argument('--ta', action="store", help="Query target address feature")
    # parser.add_argument('--qd', action="store", help="Source query (single) component differences feature")
    # parser.add_argument('--qe', action="store", help="Source query entropy feature")

    args = parser.parse_args()

    if (len(sys.argv) == 1):
        parser.print_help()
        sys.exit(-1)

    main(args)
