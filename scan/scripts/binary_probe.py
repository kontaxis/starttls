#!/usr/bin/python -u

# This script tries to identify supported ciphersuites using binary search.
# The intuition is that most servers support only a handful of suites so
# we are trying to avoid probing the majority of unsupported suites.
#
# The scripts starts with the full list of suites supported by a given prober
# (e.g., smtp_tls12_god). It splits the list in half and probes the target
# twice using these two sub-lists. If the target returns a Handshake Alert
# we can safely*(1) discard the respective sub-list since none of the suites
# on it are supported. Else, we keep going.
#
# Optimization: We are actually splitting the list based on a bias;
# creating two, probably unbalanced sub-lists, one with popular supported
# suites and one with the rest. The idea is that we are trying to quickly
# rule out the unpopular sub-list and keep working on the popular one.
# Knowledge about popular suites has been compiled empirically.
# We only split in half if all candidate suites appear in our bias.
#
# *(1): Empirical evidence identify a very rare occasion where the server
# will only consider the X first ciphersuites in a ClientHello TLS Handshake.
# This might lead to inaccurate results if the only suites the server supports
# are found near the end of the list we are probing it with.
# (server will return a Handshake Alert)
#
# kontaxis 2015-03-26

from __future__ import print_function

import argparse
import errno
import re
import time
import os
import subprocess
import sys

ciphersuite_bias = {
"0x0003": "1",
"0x0004": "1",
"0x0005": "1",
"0x0006": "1",
"0x0007": "1",
"0x0008": "1",
"0x0009": "1",
"0x000A": "1",
"0x0014": "1",
"0x0015": "1",
"0x0016": "1",
"0x0017": "1",
"0x0018": "1",
"0x0019": "1",
"0x001A": "1",
"0x001B": "1",
"0x002F": "1",
"0x0033": "1",
"0x0034": "1",
"0x0035": "1",
"0x0039": "1",
"0x003A": "1",
"0x003C": "1",
"0x003D": "1",
"0x0041": "1",
"0x0045": "1",
"0x0046": "1",
"0x0060": "1",
"0x0061": "1",
"0x0062": "1",
"0x0064": "1",
"0x0067": "1",
"0x006B": "1",
"0x006C": "1",
"0x006D": "1",
"0x0084": "1",
"0x0088": "1",
"0x0089": "1",
"0x0096": "1",
"0x009A": "1",
"0x009B": "1",
"0x009C": "1",
"0x009D": "1",
"0x009E": "1",
"0x009F": "1",
"0x00A6": "1",
"0x00A7": "1",
"0xC011": "1",
"0xC012": "1",
"0xC013": "1",
"0xC014": "1",
"0xC016": "1",
"0xC017": "1",
"0xC018": "1",
"0xC019": "1",
"0xC027": "1",
"0xC028": "1",
"0xC02F": "1",
"0xC030": "1",
}


# Expects a list of suites (hex codes) as input.
# Outputs a list of CSV strings of suites (hex codes) as output.
#
# Input is the set of suites in need of testing.
# If the target supports at least one of them, the set is split into two
# subsets and each subset is written in CSV format. Subsets are grouped
# into a list which is returned as output.
# e.g.,
#  input: ["0x0000", "0x0001", "0x0002", "0x0003"]
# output: ["0x0000,0x0001",       "0x0002,0x0003"]

expression_smtp_later = re.compile(".*(later|limit).*", re.IGNORECASE)

def generate_scan(suites):
	result = []

	global probes

	if (suites == ""):
		return []

	# Suites are split in two halves and fed to two probe instances respectively.
	firsthalf  = []
	secondhalf = []

	# Split suite list using ciphersuite_bias (more efficient that len()/2)
	for suite in suites:
		if suite in ciphersuite_bias:
			firsthalf.append(suite)
		else:
			secondhalf.append(suite)

	# If ciphersuite_bias produces an imbalance just split the suites in half
	if (len(firsthalf) == 0 or len(secondhalf) == 0):
		firsthalf  = suites[0:len(suites)/2]
		secondhalf = suites[len(suites)/2:]

	print("(%d/%d,%d) " % (len(suites), len(firsthalf), len(secondhalf)), end='')

	batches = [firsthalf, secondhalf]

	# Output rules
	opt = []
	if port == "465":
		opt.append("-d")

	# Figure out protocol of this probe
	p = subprocess.Popen([prober, "-v"], stdout=subprocess.PIPE,\
		stderr=subprocess.PIPE)
	(stdout, stderr) = p.communicate()
	proto = stderr.partition("\n")[0].split(":")[1]

	for b in batches:

		if (len(b) == 0):
			continue

		# Figure out head (first), tail (last) of suites in this batch (subset)
		c = ""
		h = b[0]
		t = b[len(b)-1]
		if h != t:
			c = "%s-%s" % (h, t)
		else:
			c = h

		print("%s:" % c, end='')

		# This should only run once and break. If the SMTP server complains
		# about the rate we retry after sleeping for a while.
		# Max sleep time is 256 seconds (4 minutes) to avoid blocking forever.
		sleeptime = 0
		max_sleeptime = 0x1 << 8

		# (stderr) output_.log
		log = None
		# (stdout) smtp_.txt
		txt = None

		while True:

			time.sleep(sleeptime)

			try:
				os.makedirs("data/%s/%s/%s/%s" % (target, port, proto, c))
			except OSError as e:
				if (e.errno != errno.EEXIST):
					print("errno.%d " % e.errno, end='')
					break

			try:
				if not log:
					log = open("data/%s/%s/%s/%s/output_%s.log" \
					% (target, port, proto, c, c), "w+")
				if not txt:
					txt = open("data/%s/%s/%s/%s/smtp_%s.txt"   \
					% (target, port, proto, c, c), "w+")
			except OSError as e:
				print("errno.%d " % e.errno, end='')
				break

			try:
				log.write("%d " % int(time.time()))

				argv = [prober, \
					"-p", port, \
					"-t", target, \
					"-x", ",".join(b), \
					"-o", "data/%s/%s/%s/%s" % (target, port, proto, c)]
				argv += opt
				# propts is last to be able to override previously set opts (e.g., -o)
				argv += propts

				# Flush stream buffers before cloning
				log.flush()

				p = subprocess.Popen(argv, stdout=txt, stderr=log)
				p.communicate()

				log.write("\n%d\n" % p.returncode)

			except Exception as e:
				print("errno.%d " % e.errno, end='')
				break

			probes += 1

			# SMTP-specific: figure out if we need to pace ourselves
			# TODO: needs more work
			txt.seek(0)
			smtp = txt.readlines()

			smtp_code = 0
			smtp_reason = None
			if (len(smtp) > 0):
				smtp_code = smtp[len(smtp)-1].partition(" ")[0]
				if (smtp_code.isdigit()):
					smtp_code = int(smtp_code)
				smtp_reason = re.match(expression_smtp_later, smtp[len(smtp)-1])

			if (smtp_code == 421) or (smtp_reason != None):
				if (sleeptime == 0):
					sleeptime = 1
				sleeptime = sleeptime * 2

				if (sleeptime <= max_sleeptime):
					print("(%d)" % sleeptime, end='')
					log.truncate(0)
					txt.truncate(0)
					continue
				else:
					print(" ", end='')
					break

			# Result. Return this half of the list if targets support something in it
			log.seek(0)
			output = log.readlines()
			r = output[len(output)-1].rstrip("\n")
			print("%s " % r, end='')

			if (int(r) == 4) and (c != ",".join(b)):
				result.append(",".join(b))

			break

		log and log.close()
		txt and txt.close()

	return result


def do_probe(suites):

	# Input is a list of suites
	# Output is a list of CSV strings of suites
	result = generate_scan(suites)

	for l in result:
		if l != suites:
			do_probe(l.split(","))


suites = []
target = ""
port   = ""
probe  = ""
propts = []

# Follow through
# By default this script will output the next set of scan rules and terminate.
follow = 0


parser = argparse.ArgumentParser(description=
	"Drive STARTTLS probes.")

parser.add_argument("--suites", "-s", nargs=1,
	help = "CSV list of ciphersuite hex codes (e.g., 0x0000 or 0x0000,0x0001)")

parser.add_argument("--probe", "-b", nargs=1,
	help = "Probe binary")

parser.add_argument("--propts", "-o", nargs=1,
	help = "Extra arguments for the Probe binary. "\
		"MUST being with a space, e.g., -o \" -d\". "\
		"You can also use this to override built-in params "\
		"such as the destination directory (-o \" -o mydatadir\").")

parser.add_argument("--target", "-t", nargs=1,
	help = "Target IPv4 address")

parser.add_argument("--port", "-p", nargs=1,
	help = "Target TCP port")

parser.add_argument("--follow", "-f",
	action="store_const", const=True, default=False,
	help = "Follow through. Don't return after one divide step.")

args = parser.parse_args()

if (args.suites):
	suites = args.suites[0].split(",")

if (args.target):
	target = args.target[0]

if (args.port):
	port   = args.port[0]

if (args.probe):
	prober = args.probe[0]

if (args.propts):
	propts = args.propts[0].lstrip().split(" ")

follow = args.follow


if (target == "") or (port == ""):
	print("# [%d] FATAL. Missing target or port." % int(time.time()),
		file=sys.stderr)
	sys.exit(-1)

if (prober == "") or (not os.path.exists(prober)):
	print("# [%d] FATAL. Prober \"%s\" not found" % (int(time.time()), prober),
		file=sys.stderr)
	sys.exit(-1)

# If suites is empty do try to get them using the probe binary
if (len(suites) == 0):
	p = subprocess.Popen([prober, "-l"], \
		stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	(stdout, stderr) = p.communicate()
	expression_suite =\
		re.compile(".* = { (0x[0-9a-z]{2},0x[0-9a-z]{2}) };$", re.IGNORECASE)
	for line in stderr.split("\n"):
		if (line == ""):
			continue
		m = re.match(expression_suite, line)
		if (m == None):
			continue
		suites.append(m.group(1).replace(",0x", ""))

t1 = time.time()

probes = 0

print("# [%d] %s %s %s " % (int(t1), target, port, prober), end='')

if (follow == True):
	do_probe(suites)
else:
	result = generate_scan(suites)

t2 = time.time()

print(" %d seconds elapsed (%d probes used)" % (int(t2-t1), probes))

# Output follow-up rules
if (follow == False):
	for l in result:
		print("%s -t %s -p %s -b \"%s\" -s %s" % \
			(sys.argv[0], target, port, prober, l), end='')
		if (len(propts) != 0):
			print(" -o \" %s\"" % " ".join(propts))
		else:
			print("")
