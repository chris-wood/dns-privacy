import sys

fout = sys.argv[1]
string = sys.argv[2]

if "," not in string:
    with open(fout, "w") as fh:
        fh.write(string + "\n")
