#!/bin/bash

# This script makes sure that generated traffic dumps
# (e.g., for SMTP and SSL/TLS) are accurate.
# 
# kontaxis 2014-10-06

target=$1;

if [ "${target}" == "" ]; then
	>&2 echo "Fatal. Missing target IP address.";
	exit -1;
fi

probers=(\
"../../../bin/smtp_ssl3_god"  \
"../../../bin/smtp_tls1_god"  \
"../../../bin/smtp_tls11_god" \
"../../../bin/smtp_tls12_god" \
)

for e in ${probers[*]}; do
	if [ ! -e "${e}" ]; then
		>&2 echo "Fatal. Missing prober '${e}'";
		exit -1;
	fi
done

tshark=`sudo which tshark`
openssl=`which openssl`

if [ "${tshark}" == "" ]; then
	>&2 echo "Fatal. Missing tshark.";
	exit -1
fi

if [ "${openssl}" == "" ]; then
	>&2 echo "Fatal. Missing openssl.";
	exit -1
fi


# for each prober, run it while capturing raw packets on the same interface.
# once done, compare the traffic dump and the packet dump.
for e in ${probers[*]}; do
for c in {0x00,0x04}; do # try with an unsupported and a supported cipher
	# start capturing packets on TCP 25
	echo "Starting packet capture..."
	sudo -b ${tshark} -n -i eth0 host ${target} and tcp and port 25 -w /tmp/tcp25.tshark &> /dev/null

	echo "Sleeping 5..."
	sleep 5;

	# run prober
	rm -f ssl.3.*;
	echo "Running prober..."
	${e} -t ${target} -p 25 -x ${c} > smtp.txt 2> log.txt
	r=$?
	#  4: ERROR_NONE (Success)
	# 30: ERROR_TLS  (TLS handshake failed, e.g., unsupported ciphersuite)
	if [ "${r}" != "4" ] && [ "${r}" != "30" ]; then
		>&2 echo "Fatal. Trouble(${r}). Check log.txt";
		exit 1;
	fi

	# stop capturing packets
	echo "Stopping packet capture..."
	sudo -b killall tshark &> /dev/null

	echo "Sleeping 5..."
	sleep 5;

	sudo chmod +r /tmp/tcp25.tshark &> /dev/null

	echo "Processing..."

	# transform packet dump into a raw payload dump
	${tshark} -r /tmp/tcp25.tshark -T fields -e data -qz follow,tcp,raw,0 | tail -n +7 | tr -d '=\r\n\t' | xxd -r -p > tcp25.tshark-raw 2> /dev/null

	# construct final traffic dump
	cat smtp.txt > tcp25.dump 2> /dev/null
	cat ssl.3.* >> tcp25.dump 2> /dev/null

	x=`openssl md5 tcp25.dump 2>&1 | awk '{print $2}'`
	y=`openssl md5 tcp25.tshark-raw 2>&1 | awk '{print $2}'`

	echo -n "${e} "

	if [ "${x}" == "${y}" ]; then
		echo -e "\033[1;32mSUCCEEDED\033[0m $c $x `ls -l tcp25.dump | awk '{print $5}'` dumped bytes $y `ls -l tcp25.tshark-raw | awk '{print $5}'` captured bytes"
	else
		echo -e "\033[1;31mFAILED\033[0m $c $x `ls -l tcp25.dump | awk '{print $5}'` dumped bytes $y `ls -l tcp25.tshark-raw | awk '{print $5}'` captured bytes"
		exit -1
	fi
done
done
