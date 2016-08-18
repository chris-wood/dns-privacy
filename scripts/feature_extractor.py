#!/usr/bin/env python

import sys
import math
import statistics
import argparse
from pcap_parser import *

#### DONE
# DONE 1. Relative (per-user) query length
# DONE 2. Relative source query frequency
# DONE 3. Relative target query frequency
# DONE 4. Query resolution length (time)
# DONE 8. Query target address
# ADDED: Query target name (different from above since a name could map to different addresses)
# DONE 7. Query diversity entropy
# DONE 9. Query diversity stddev
# DONE 10. Query diversity number of URI component differences

#### Requires more than one PCAP file (into and out of a resolver)
# 10. Resolution chain length (number of recursive queries)
# 11. Resolution chain (domains in the chain itself)

def computeComponentDifferences(s1, s2):
    if len(s1) > len(s2):
        s1,s2 = s2,s1
    distances = range(len(s1) + 1)
    for index2, elem2 in enumerate(s2):
        elem2 = elem2.lower()
        newDistances = [index2 + 1]
        for index1, elem1 in enumerate(s1):
            elem1 = elem1.lower()
            if elem1 == elem2:
                newDistances.append(distances[index1])
            else:
                newDistances.append(1 + min((distances[index1], distances[index1 + 1], newDistances[-1])))
        distances = newDistances
    return distances[-1]

def computeQueryDifferences(queries):
    differences = 0
    for firstIndex, v1 in enumerate(queries):
        for secondIndex, v2 in enumerate(queries):
            if firstIndex != secondIndex:
                query1 = v1.split(".")
                query2 = v2.split(".")

                diff = computeComponentDifferences(query1, query2)
                differences += diff
    return differences

def computeQueryEntropy(queries):
    prob = {}
    total = 0
    for query in queries:
        if query.name not in prob:
            prob[query.name] = 0
            total += 1
        prob[query.name] += 1

    # compute the entropy
    # H= -\sum p(x) log p(x)
    acc = 0
    for name in prob:
        p = float(prob[name]) / float(total)
        logp = math.log(p)
        acc += (p * logp)
    entropy = acc * -1

    return entropy

def computeQueryFrequency(queries, window):
    return float(len(queries)) / float(window)

class WindowFeatureExtractor(object):
    def __init__(self, window, processingFunction):
        self.window = window
        self.processingFunction = processingFunction

    def process(self, packets):
        return self.processingFunction(queries)

class FeatureFormatter(object):
    ''' Class that formats lists of features for the output
    '''
    def __init__(self, features):
        self.features = features # list of tuples

    def toCSV(self, stream = None):
        lines = []
        for f in self.features:
            line = ",".join(map(lambda x : str(x), f))
            if len(line) > 1:
                lines.append(line)
                if stream != None:
                    stream.write(line)
        return "\n".join(lines)

class FeatureExtractor(object):
    ''' Base class for all feature extractors.
    '''
    def __init__(self, packets, params = {}, outputPackets = None):
        self.packets = packets
        self.params = params
        self.outputPackets = outputPackets

    def getPacketsFromSourceInWindow(self, offset, src, window):
        packetsSent = []
        firstPacket = self.packets[offset]
        while offset < len(self.packets):
            packet = self.packets[offset]
            if packet.query != None and packet.query.srcAddress == src:
                packetsSent.append(packet.query)
                if packet.ts - firstPacket.ts > window:
                    break
            offset += 1
        return packetsSent, offset

    def extract(self, index, params = {}):
        pass

class TestFeatureExtractor(FeatureExtractor):
    ''' Template for new feature extractors
    '''
    def __init__(self, packets, params = {}):
        FeatureExtractor.__init__(self, packets, params)

    def extract(self, index, params = {}):
        features = []
        sources = {}

        # for packet in self.packets:
        #     pass

        return features, sources

class WindowedFeatureExtractor(FeatureExtractor):
    def __init__(self, packets, windowExtractor):
        FeatureExtractor.__init__(self, packets)
        self.extractor = windowExtractor

    def extract(self, index):
        features = []
        sources = {}

        window = self.extractor.window

        i = index
        while i < len(self.packets) - 1:
            packet = self.packets[i]
            offset = i + 1

            if packet.query != None:
                src = packet.query.srcAddress
                packetsSent, offset = self.getPacketsFromSourceInWindow(offset, src, window)
                featureValue = self.extractor(queriesSent)
                if src not in sources:
                    sources[src] = len(sources)
                feature = (sources[src], featureValue)
                features.append(feature)

                return features, sources

            i = offset

        return features, sources

        return features

class QueryComponentDifferenceDiversityFeatureExtractor(FeatureExtractor):
    def __init__(self, packets, params = {}):
        FeatureExtractor.__init__(self, packets, params)

    def extract(self, index):
        features = []
        sources = {}

        window = self.params["window"]

        i = index
        while i < len(self.packets) - 1:
            packet = self.packets[i]
            offset = i + 1

            if packet.query != None:
                src = packet.query.srcAddress
                packetsSent, offset = self.getPacketsFromSourceInWindow(offset, src, window)

                differences = computeQueryDifferences(packetsSent)

                if src not in sources:
                    sources[src] = len(sources)
                feature = (sources[src], differences)
                features.append(feature)

                return features, sources

            i = offset

        return features, sources

class QueryEntropyDiversityFeatureExtractor(FeatureExtractor):
    def __init__(self, packets, params = {}):
        FeatureExtractor.__init__(self, packets, params)

    def extract(self, index):
        features = []
        sources = {}

        window = self.params["window"]

        i = index
        while i < len(self.packets) - 1:
            packet = self.packets[i]
            offset = i + 1

            if packet.query != None:
                src = packet.query.srcAddress
                packetsSent, offset = self.getPacketsFromSourceInWindow(offset, src, window)

                entropy = computeQueryEntropy(packetsSent)

                if src not in sources:
                    sources[src] = len(sources)
                feature = (sources[src], entropy)
                features.append(feature)

                return features, sources

            i = offset

        return features, sources

class TargetQueryFrequencyFeatureExtractor(FeatureExtractor):
    def __init__(self, packets, params = {}):
        FeatureExtractor.__init__(self, packets, params)

    def extract(self, index):
        sources = {}
        features = []

        window = self.params["window"]

        i = index
        while i < len(self.packets) - 1:
            packet = self.packets[i]
            offset = i + 1

            if packet.query != None:
                src = packet.query.srcAddress
                packetsSent, offset = self.getPacketsFromSourceInWindow(offset, src, window)

                frequency = computeQueryFrequency(packetsSent, window)

                if src not in sources:
                    sources[src] = len(sources)
                feature = (sources[src], frequency)
                features.append(feature)

                return features, sources

                # Since we're concerned with target frequency, the window only
                # moves forward when the target query changes
                targetName = packet.query.name
                for index, packet in enumerate(packetsSent):
                    if packet.query.name != targetName and index != 0:
                        offset = i + index

            i = offset

        return features, sources

class QueryFrequencyFeatureExtractor(FeatureExtractor):
    def __init__(self, packets, params = {}):
        FeatureExtractor.__init__(self, packets, params)

    def extract(self, index):
        features = []
        sources = {}

        window = self.params["window"]

        i = index
        while i < len(self.packets) - 1:
            packet = self.packets[i]
            offset = i + 1

            if packet.query != None:
                src = packet.query.srcAddress
                packetsSent, offset = self.getPacketsFromSourceInWindow(offset, src, window)

                frequency = computeQueryFrequency(packetsSent, window)

                if src not in sources:
                    sources[src] = len(sources)
                feature = (sources[src], frequency)
                features.append(feature)

                return features, sources

            i = offset

        return features, sources

class TargetAddressFeatureExtractor(FeatureExtractor):
    def __init__(self, packets, params = {}):
        FeatureExtractor.__init__(self, packets, params)

    def extract(self, index):
        features = []
        sources = {}

        for packet in self.packets:
            for record in packet.records:
                src = record.srcAddress
                if record.targetAddress != None:
                    target = record.targetAddress

                    if src not in sources:
                        sources[src] = len(sources)
                    feature = (sources[src], target)

                    features.append(feature)

        return features, sources

class TargetNameFeatureExtractor(FeatureExtractor):
    def __init__(self, packets, params = {}):
        FeatureExtractor.__init__(self, packets, params)

    def extract(self, index):
        features = []
        sources = {}

        for packet in self.packets:
            if packet.query != None:
                src = packet.query.srcAddress
                target = packet.query.name
                if src not in sources:
                    sources[src] = len(sources)
                feature = (sources[src], target)

                features.append(feature)

        return features, sources

class QueryResolutionTimeFeatureExtractor(FeatureExtractor):
    def __init__(self, packets, params = {}):
        FeatureExtractor.__init__(self, packets, params)

    def extract(self, index, params = {}):
        features = []
        sources = {}

        packet = self.packets[index]

        # Match queries to responses, so only start searching from queries
        if packet.query != None:
            src = packet.query.srcAddress
            target = packet.query.name
            for response in self.packets[index:]:
                if len(response.records) > 0 and response.records[0].target == target:
                    match = response.records[0]
                    delta = response.ts - packet.ts
                    if delta > 0:
                        if src not in sources:
                            sources[src] = len(sources)
                        feature = (sources[src], delta)

                        features.append(feature)

        return features, sources

class QueryLengthFeatureExtractor(FeatureExtractor):
    def __init__(self, packets, params = {}):
        FeatureExtractor.__init__(self, packets, params)

    def extract(self, index):
        sources = {}
        features = []

        packet = self.packets[index]
        if packet.query != None:
            src = packet.query.srcAddress
            queryLength = len(packet.query.name)

            if src not in sources:
                sources[src] = len(sources)
            feature = (sources[src], queryLength)

            features.append(feature)
        if len(packet.records) > 0:
            src = packet.records[0].dstAddress
            queryLength = len(packet.records[0].target)

            if src not in sources:
                sources[src] = len(sources)
            feature = (sources[src], queryLength)

            features.append(feature)
        return features, sources

def join(featureSet):
    if len(featureSet) == 1:
        return featureSet[0]
    else:
        index = 0
        numFeatures = len(featureSet) - 1
        joinedFeatures = []
        for features in featureSet:

            # features = list of tuples == [(0,19),(0,19),...]

            for feature in features:
                entry = [feature[0]] # feature[0] is always the source -- could be wrapped up in a class
                for i in range(index):
                    entry.append(0)
                entry.append(feature[1])
                for i in range(numFeatures - index):
                    entry.append(0)
                joinedFeatures.append(entry)

            index += 1
        return joinedFeatures

def extract(dnsPackets, extractors):
    featureSet = []
    sourceSet = {}
    for index, packet in enumerate(dnsPackets):
        if isinstance(packet, ResourceRecord):
            continue

        sources = set()
        features = {}

        for eindex, extractor in enumerate(extractors):
            # Extract one feature set from the chain starting at the current packet
            single_features, single_sources = extractor.extract(index)

            if eindex not in features:
                features[eindex] = []

            # Add new sources to the main source list, if needed
            for source in single_sources:
                if source not in sourceSet:
                    sourceSet[source] = len(sourceSet)

            # Re-build feature entries and add them to a list
            for feature in single_features:
                sourceId = feature[0]
                value = feature[1]
                for source in single_sources:
                    if single_sources[source] == sourceId:
                        adjustedSourceId = sourceSet[source]
                        features[eindex].append([adjustedSourceId, value])
            else:
                source = packet.src
                if source not in sourceSet:
                    sourceSet[source] = len(sourceSet)
                adjustedSourceId = sourceSet[source]
                features[eindex].append([adjustedSourceId, 0]) # null feature...

        # Merge each feature entry tuple
        merged_feature = [packet.src]
        for feature_index in features:
            for value_tuple in features[feature_index]:
                merged_feature.append(value_tuple[1])
                break # only use the first feature

        featureSet.append(merged_feature)

    # Format the feature using CSV (maybe later add more formatting options)
    formatter = FeatureFormatter(featureSet)
    formatter.toCSV()

    return featureSet

def main(args):
    filenames = args.file
    print >> sys.stderr, "$> Parsing...", filenames

    dnsPackets = []
    for filename in filenames:
        parser = PacketParser(filename)
        packets = parser.parseDNS(filename)
        for packet in packets:
            dnsPackets.append(packet)

    # Initialize the extractors
    extractors = []
    for key in vars(args):
        val = vars(args)[key]

        if key == "ql" and val:
            extractors.append(QueryLengthFeatureExtractor(dnsPackets))
        elif key == "qr" and val:
            extractors.append(QueryResolutionTimeFeatureExtractor(dnsPackets))
        elif key == "qf" and val != None:
            extractors.append(QueryFrequencyFeatureExtractor(dnsPackets, params = {"window" : float(val)}))
        elif key == "tf" and val != None:
            extractors.append(TargetQueryFrequencyFeatureExtractor(dnsPackets, params = {"window" : float(val)}))
        elif key == "tn" and val:
            extractors.append(TargetNameFeatureExtractor(dnsPackets))
        elif key == "ta" and val:
            extractors.append(TargetAddressFeatureExtractor(dnsPackets))
        elif key == "qd" and val != None:
            extractors.append(QueryComponentDifferenceDiversityFeatureExtractor(dnsPackets, params = {"window" : float(val)}))
        elif key == "qe" and val != None:
            extractors.append(QueryEntropyDiversityFeatureExtractor(dnsPackets, params = {"window" : float(val)}))

    output = extract(dnsPackets, extractors)
    print >> sys.stdout, output
    print >> sys.stderr, "$> Done. Parsed %d individual DNS packet(s)" % len(dnsPackets)

if __name__ == "__main__":
    desc = '''
Parse a PCAP file and extract a set of features for classification.
'''

    parser = argparse.ArgumentParser(prog='feature_extractor', formatter_class=argparse.RawDescriptionHelpFormatter, description=desc)
    parser.add_argument('-f', '--file', action="store", required=True, help="Relative path to PCAP file to parse", nargs="+")
    parser.add_argument('--ql', default=False, action="store_true", help="Query length feature")
    parser.add_argument('--qr', default=False, action="store_true", help="Query resolution time feature")
    parser.add_argument('--tn', default=False, action="store_true", help="Query target name feature")
    parser.add_argument('--qf', action="store", help="Query frequency with parameterized window")
    parser.add_argument('--tf', action="store", help="Source target frequency with parameterized window")
    parser.add_argument('--ta', action="store", help="Query target address feature")
    parser.add_argument('--qd', action="store", help="Source query (single) component differences feature")
    parser.add_argument('--qe', action="store", help="Source query entropy feature")

    args = parser.parse_args()

    if (len(sys.argv) == 1):
        parser.print_help()
        sys.exit(-1)

    main(args)
