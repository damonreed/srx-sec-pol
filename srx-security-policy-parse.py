#
# srx-security-policy-parse.py
#

"""
srx-security-policy-parse.py

Given a "display set" version of an SRX config, it will generate a CSV output
file summarizing each policy grouped by from-zone + to-zone and then
listed in order of evaluation.

"""

import os
import re
import sys

from copy import deepcopy


def parseConfig(cfgFile):

    policy_template = {
        "count": 0,
        "from-zone": "",
        "to-zone": "",
        "policy": "",
        "source-address": [],
        "destination-address": [],
        "application": [],
        "action": ""
    }
    policies = {}
    polCount = {}
    polResult = []

    f = open(cfgFile, "r")

    regex = r'from-zone (\S+) to-zone (\S+) policy (\S+) (match|then) (\S+)\s*(\S*)'

    for line in f.readlines():

        entry = []

        match = re.search(regex, line)

        if match:
            entry = match.groups()

            if not entry[2] in policies:
                policies[entry[2]] = deepcopy(policy_template)
                policies[entry[2]]["policy"] = entry[2]

            if entry[3] == "match":
                policies[entry[2]][entry[4]].append(entry[5])
            elif entry[3] == "then":
                if entry[4] == "permit" or entry[4] == "deny":
                    policies[entry[2]]["action"] = entry[4]
                    if entry[0] + "-" + entry[1] in polCount:
                        polCount[entry[0] + "-" + entry[1]] += 1
                    else:
                        polCount[entry[0] + "-" + entry[1]] = 1
                    policies[entry[2]]["count"] = polCount[entry[0] + "-" + entry[1]]
                    policies[entry[2]]["from-zone"] = entry[0]
                    policies[entry[2]]["to-zone"] = entry[1]

        f.close

    for policy in sorted(policies, key=lambda x: policies[x]["from-zone"] + policies[x]["to-zone"] + "%4d" % policies[x]["count"]):

        lFZ = policies[policy]["from-zone"]
        lTZ = policies[policy]["to-zone"]
        lDex = policies[policy]["count"]
        lPol = policies[policy]["policy"]
        lSrc = "\n".join(policies[policy]["source-address"])
        lDst = "\n".join(policies[policy]["destination-address"])
        lAct = policies[policy]["action"]
        lApp = "\n".join(policies[policy]["application"])

        polLine = '"%s","%s","%d","%s","%s","%s","%s","%s"\n' % (
            lFZ, lTZ, lDex, lPol, lSrc, lDst, lAct, lApp)

        polResult.append(polLine)

    return "".join(polResult)


def main():
    args = sys.argv[1:]

    # if not args:
    #     print("usage: [--outfile file] configfile")
    #     sys.exit(1)

    outFile = ''
    if args[0] == '--outfile':
        outFile = args[1]
        del args[0:2]

    if args[0]:
        cfgFile = args[0]
    else:
        cfgFile = "srx.cfg"

    if not os.path.isfile(cfgFile):
        print("%s: file not found" % cfgFile)
        sys.exit(1)

    if outFile:
        wfile = open(outFile, "w")
        wfile.write(parseConfig(cfgFile))
        wfile.close
    else:
        print(parseConfig(cfgFile))


if __name__ == '__main__':
    main()
