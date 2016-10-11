#!/usr/bin/env python

import sys
import math
import statistics
import argparse
import networkx
from pcap_parser import *

###

def main(args):
    pass

if __name__ == "__main__":
    desc = '''
Build a domain relationship graph from PCAP files.
'''

    parser = argparse.ArgumentParser(prog=sys.argv[0], formatter_class=argparse.RawDescriptionHelpFormatter, description=desc)
    parser.add_argument('-f', '--file', action="store", required=True, help="Relative path to PCAP file to parse", nargs="+")
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
