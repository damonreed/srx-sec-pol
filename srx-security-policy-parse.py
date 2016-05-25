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

cfgFile = "sample.cfg"
outFile = "policies.csv"

policy_template = {
    "count" : 0,
	"from-zone" : "",
	"to-zone" : "",
	"policy" : "",
	"source-address": [],
	"destination-address": [],
	"application": [],
	"action": ""
}

policies = {}
polCount = {}

print "Parsing file:",cfgFile

f = open(cfgFile,"r")

regex = r'from-zone (\S+) to-zone (\S+) policy (\S+) (match|then) (\S+)\s*(\S*)'

for line in f.readlines():

    entry = []

    match = re.search( regex , line )

    if match:
        entry = match.groups()

        if not entry[2] in policies:
            policies[entry[2]] = deepcopy(policy_template)
            policies[entry[2]]["policy"] = entry[2]

        if entry[3] == "match":
            #print entry[2],entry[4],entry[5]
            policies[entry[2]][entry[4]].append(entry[5])
        elif entry[3] == "then":
            if entry[4] == "permit" or entry[4] == "deny":
                policies[entry[2]]["action"] = entry[4]
                if entry[0]+"-"+entry[1] in polCount:
                    polCount[entry[0]+"-"+entry[1]] += 1
                else:
                    polCount[entry[0]+"-"+entry[1]] = 1
                policies[entry[2]]["count"] = polCount[entry[0]+"-"+entry[1]]
                policies[entry[2]]["from-zone"] = entry[0]
                policies[entry[2]]["to-zone"] = entry[1]

#print policies
wfile = open(outFile,"w")

for policy in sorted(policies, key=lambda x : policies[x]["from-zone"] + policies[x]["to-zone"] + "%4d" % policies[x]["count"]):

    lFZ = policies[policy]["from-zone"]
    lTZ = policies[policy]["to-zone"]
    lDex = policies[policy]["count"]
    lPol = policies[policy]["policy"]
    lSrc = "\n".join(policies[policy]["source-address"])
    lDst = "\n".join(policies[policy]["destination-address"])
    lAct = policies[policy]["action"]
    lApp = "\n".join(policies[policy]["application"])

    polLine = '"%s","%s","%d","%s","%s","%s","%s","%s"\n' % (lFZ,lTZ,lDex,lPol,lSrc,lDst,lAct,lApp)

    print polLine

    wfile.write(polLine)
    #print policies[policy]["policy"], policies[policy]["source-address"],
    #print policies[policy]["destination-address"],
    #print policies[policy]["action"]+": "+str(policies[policy]["application"])
    #print "***"

wfile.close
f.close
