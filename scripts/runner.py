#!/usr/bin/env python

import sys
import math
import statistics
import argparse
import itertools

from pcap_parser import *
from feature_extractor import *
from classifier import *

def build_extractors(dnsPackets, windows = [0.5, 1, 5, 10]):
    extractors = []

    extractors.append(QueryLengthFeatureExtractor(dnsPackets))
    extractors.append(QueryResolutionTimeFeatureExtractor(dnsPackets))
    # extractors.append(TargetNameFeatureExtractor(dnsPackets))
    # extractors.append(TargetAddressFeatureExtractor(dnsPackets))

    # Initialize the dynamic ones with a bunch of different window values
    for window in windows:
        extractors.append(QueryComponentDifferenceDiversityFeatureExtractor(dnsPackets, params = {"window" : float(window)}))
        extractors.append(QueryEntropyDiversityFeatureExtractor(dnsPackets, params = {"window" : float(window)}))
        extractors.append(QueryFrequencyFeatureExtractor(dnsPackets, params = {"window" : float(window)}))
        extractors.append(TargetQueryFrequencyFeatureExtractor(dnsPackets, params = {"window" : float(window)}))

    return extractors

def run_classifiers(identifier, data):
    testPercentage = 0.1
    iterations = 1000
    options = ""

    print data

    numberOfUsers = np.amax([map(float, column[1:]) for column in data][0:len(data)])
    classifiers = get_classifiers().split(",")

    for num_of_classifiers in range(1, len(classifiers) + 1):
        for subset in itertools.combinations(classifiers, num_of_classifiers):
            classifier_subset = ",".join(subset)
            errorRate, startTime, endTime = run(data, numberOfUsers, testPercentage, classifier_subset, iterations, options)

            print >> sys.stderr, ""
            print >> sys.stderr, "Execution time: " + str(datetime.timedelta(seconds=(endTime - startTime)))
            print >> sys.stderr, "Error rate: " + str(errorRate / iterations)
            print >> sys.stderr, "Number of users: " + str(numberOfUsers)
            print >> sys.stdout, identifier + "\t" +\
                classifier_subset + "\t" +\
                options + "\t" +\
                str(datetime.timedelta(seconds=(endTime - startTime))) + "\t" +\
                str(errorRate / iterations) + "\t" +\
                str(numberOfUsers)

def main(args):
    filenames = args.file
    dnsPackets = []
    for filename in filenames:
        parser = PacketParser()
        fh = open(filename, 'r')
        packets = parser.parseDNS(fh)
        for packet in packets:
            dnsPackets.append(packet)

    extractors = build_extractors(dnsPackets)
    for num_of_extractors in range(1, len(extractors) + 1):
        for subset in itertools.combinations(extractors, num_of_extractors):
            features = extract(dnsPackets, subset)
            if features != None:
                identifier = "-".join(map(lambda e : str(e), list(subset)))
                run_classifiers(identifier, features)
            else:
                print "Null features %s" % (str(subset))

if __name__ == "__main__":
    desc = '''
Parse a PCAP file and extract a set of features for classification.
'''
    parser = argparse.ArgumentParser(prog='runner', formatter_class=argparse.RawDescriptionHelpFormatter, description=desc)
    parser.add_argument('-f', '--file', action="store", required=True, help="Relative path to PCAP file(s) to parse", nargs="+")

    args = parser.parse_args()
    main(args)
