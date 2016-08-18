import sys, getopt
import math
import time
import datetime
import numpy as np
from random import shuffle
from sklearn.linear_model import SGDClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression


class color:
   PURPLE = '\033[95m'
   CYAN = '\033[96m'
   DARKCYAN = '\033[36m'
   BLUE = '\033[94m'
   GREEN = '\033[92m'
   YELLOW = '\033[93m'
   RED = '\033[91m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'
   END = '\033[0m'

def readInput(fileName):
   rows = []
   with open(fileName, "r") as csvfile:
      for row in csvfile:
         chunks = row.rstrip().split(',')
         if len(chunks) != 0:
            rows.append(chunks)
   return rows

def get_classifiers():
    return "sgd,tree,svm,logistic"

def processInput(data, testPercentage):
   shuffle(data)
   testSize = int(math.floor(len(data) * testPercentage))

   trainingFeatures = [map(float, column[1:]) for column in data][0:len(data) - testSize]
   trainingTarget = [column[0] for column in data][0:len(data) - testSize]
   testFeatures = [map(float, column[1:]) for column in data][-testSize:]
   testTarget = [column[0] for column in data][-testSize:]

   return (trainingFeatures, trainingTarget, testFeatures, testTarget)


def sgd(trainingFeatures, trainingTarget, testFeatures, testTarget, options):
   lossFunction = "hinge"
   iterations = 200
   if options != "":
      chunks = options.split(",")
      if chunks[0] in ("hinge", "log", "modified_huber", "squared_hinge"):
         lossFunction = chunks[0]
      else:
         print >> sys.stderr, color.RED + "SGD loss function is not recognized" + color.END
         usage()
         sys.exit(2)

      if chunks[1].isdigit() and int(chunks[1]) > 0:
         iterations = int(chunks[1])
      else:
         print >> sys.stderr, color.RED + "SGD number of epoch must be a positive non-zero number" + color.END
         usage()
         sys.exit(2)

   clf = SGDClassifier(loss=lossFunction, n_iter=iterations)
   clf.fit(trainingFeatures, trainingTarget)
   return clf.predict(testFeatures)


def tree(trainingFeatures, trainingTarget, testFeatures, testTarget):
   clf = DecisionTreeClassifier()
   clf.fit(trainingFeatures, trainingTarget)
   return clf.predict(testFeatures)


def svm(trainingFeatures, trainingTarget, testFeatures, testTarget):
   clf = SVC()
   clf.fit(trainingFeatures, trainingTarget)
   return clf.predict(testFeatures)


def logistic(trainingFeatures, trainingTarget, testFeatures, testTarget, options):
   regularization = 1.0
   if options != "":
      try:
         regularization = float(options)
      except ValueError:
         print >> sys.stderr, color.RED + "Logistic Regression regularization must be a float number" + color.END
         usage()
         sys.exit(2)

   clf = LogisticRegression(C=regularization)
   clf.fit(trainingFeatures, trainingTarget)
   return clf.predict(testFeatures)


def error(testTarget, testTargetPredicted):
   count = 0
   for i in range(0, len(testTarget)):
      tmp = []
      for j in range(0, len(testTargetPredicted)):
         # testTargetPredicted: rows and columns are swapped
         tmp.append(testTargetPredicted[j][i])

      if (max(set(tmp), key=tmp.count) != testTarget[i]):
         count = count + 1

   return ((1.0 * count) / len(testTarget))

def run(data, numberOfUsers, testPercentage, classifiers, iterations, options):
   # print >> sys.stderr, "Input file: " + fileName
   print >> sys.stderr, "Classifiers: " + classifiers
   print >> sys.stderr, "Options: " + options
   print >> sys.stderr, ""

   print >> sys.stderr, "Reading input file..."

   errorRate = 0.0
   startTime = time.time()
   for i in range(0, iterations):
      print >> sys.stderr, "\rIteration " + str(i + 1) + ":",
      trainingFeatures, trainingTarget, testFeatures, testTarget = processInput(data, testPercentage)
      testTargetPredicted = []
      for cls in classifiers.split(","):
         if cls == "sgd":
            print >> sys.stderr, "running SGD...",
            testTargetPredicted.append(sgd(trainingFeatures, trainingTarget, testFeatures, testTarget, options))
         elif cls == "tree":
            print >> sys.stderr, "running Decision Tree...",
            testTargetPredicted.append(tree(trainingFeatures, trainingTarget, testFeatures, testTarget))
         elif cls == "svm":
            print >> sys.stderr, "running SVM...",
            testTargetPredicted.append(svm(trainingFeatures, trainingTarget, testFeatures, testTarget))
         elif cls == "logistic":
            print >> sys.stderr, "running Logistic Regression...",
            testTargetPredicted.append(logistic(trainingFeatures, trainingTarget, testFeatures, testTarget, options))
         else:
            print >> sys.stderr, color.RED + "Unknown classifier" + color.END
            usage()
            sys.exit(2)

      print >> sys.stderr, "calculating error...",
      errorRate = errorRate + error(testTarget, testTargetPredicted)

   endTime = time.time()

   return errorRate, startTime, endTime

def usage():
   print >> sys.stderr, "usage: classifier -i FILE [-p PERCENTAGE] -c CLASSIFIERS [-t ITERATIONS] [-o OPTIONS]"
   print >> sys.stderr, ""
   print >> sys.stderr, "Run a set of classifiers on features extracted from DNS traces and calculate error rate."
   print >> sys.stderr, ""
   print >> sys.stderr, "arguments:"
   print >> sys.stderr, "  -h, --help                                 show this help message and exit"
   print >> sys.stderr, "  -i FILE, --ifile FILE                      relative path to csv containing: first column is target and rest are features"
   print >> sys.stderr, "  -p PERCENTAGE, --percentage PERCENTAGE     the percentage of input data to be treated as test data, range [0, 1]"
   print >> sys.stderr, "  -c CLASSIFIERS, --classifiers CLASSIFIERS  comma seperated list of one or more classifiers to use in prediction"
   print >> sys.stderr, "                                             Options are: sgd, tree, svm, logistic"
   print >> sys.stderr, "  -t ITERATIONS, --iterations ITERATIONS     number of classification iterations"
   print >> sys.stderr, "  -o OPTIONS, --option OPTION                options to pass to the classifiers"
   print >> sys.stderr, "                                               " + color.UNDERLINE + "sgd:" + color.END +\
      " [loss={'hinge', 'log', 'modified_huber', 'squared_hinge'}],n_iter=INT]"
   print >> sys.stderr, "                                               " + color.UNDERLINE + "tree:" + color.END + " none"
   print >> sys.stderr, "                                               " + color.UNDERLINE + "svm:" + color.END + " none"
   print >> sys.stderr, "                                               " + color.UNDERLINE + "logistic:" + color.END + " [regularization=FLOAT]"

def main(argv):
   fileName = ""
   testPercentage = 0.1
   classifiers = ""
   iterations = 1
   options = ""
   try:
      opts, args = getopt.getopt(argv, "hi:p:c:t:o:",
                                 ["ifile=", "percentage=", "classifiers=",
                                  "iterations=", "options="])
   except getopt.GetoptError:
      usage()
      sys.exit(2)

   if (len(opts) < 2):
      usage()
      sys.exit(2)

   for opt, arg in opts:
      if opt == "-h":
         usage()
         sys.exit()
      elif opt in ("-i", "--ifile"):
         fileName = arg
      elif opt in ("-p", "--percentage"):
         testPercentage = float(arg)
      elif opt in ("-c", "--classifiers"):
         classifiers = arg
      elif opt in ("-t", "--iterations"):
         iterations = int(arg)
      elif opt in ("-o", "--options"):
         options = arg
      else:
         usage()
         sys.exit(2)

   if fileName == "":
      print >> sys.stderr, color.RED + "Input file must be specified." + color.END
      usage()
      sys.exit(2)

   if classifiers == "":
      print >> sys.stderr, color.RED + "Classifier(s) must be specified." + color.END
      usage()
      sys.exit(2)

   data = readInput(fileName)
   numberOfUsers = np.amax([map(float, column[1:]) for column in data][0:len(data)])
   errorRate, startTime, endTime = run(data, numberOfUsers, testPercentage, classifiers, iterations, options)

   print >> sys.stderr, ""
   print >> sys.stderr, "Execution time: " + str(datetime.timedelta(seconds=(endTime - startTime)))
   print >> sys.stderr, "Error rate: " + str(errorRate / iterations)
   print >> sys.stderr, "Number of users: " + str(numberOfUsers)
   print >> sys.stdout, fileName + "\t" +\
      classifiers + "\t" +\
      options + "\t" +\
      str(datetime.timedelta(seconds=(endTime - startTime))) + "\t" +\
      str(errorRate / iterations) + "\t" +\
      str(numberOfUsers)


if __name__ == "__main__":
   main(sys.argv[1:])
