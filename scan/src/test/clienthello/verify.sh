#!/bin/bash

# This script makes sure the ClientHello message is properly constructed.
# (ciphersuite encoding, protocol version, length, etc.)
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

clienthellotemplate="0x16 0x03 0x0V 0x002D 0x01 0x000029 0x03 0x0V 0x00000000 0x00000000000000000000000000000000000000000000000000000000 0x00 0x0002 CCCCCC 0x01 0x00 ";

for e in ${probers[*]}; do
	if [ ! -e "${e}" ]; then
		>&2 echo "Fatal. Missing prober '${e}'";
		exit -1;
	fi
done

for e in ${probers[*]}; do
	suites=`${e} -l |& awk '{print $6}' | sed s/",0x"/""/g`;

	for s in $suites; do
		rm -f ssl.*;

		${e} -t ${target} -x ${s} > /dev/null 2> log.txt
		r=$?
		if [ "${r}" != "0" ] && [ "${r}" != "30" ]; then
			>&2 echo "Fatal. Trouble(${r}). Check log.txt";
			exit 1;
		fi

		./dump_ClientHello.sh ssl.* > /dev/null 2> dump.txt
		t=`cat dump.txt | tr -d '\n'`

		v=`${e} -v |& head -n 1 | tr -d '\n' | tail -c 1`
		c=`echo "${clienthellotemplate}" | sed s/"V"/"${v}"/g | sed s/"CCCCCC"/${s}/g`;

		if [ "${t}" == "${c}" ]; then
			echo -e "${e} ${s} \033[1;32mSUCCEEDED\033[0m";
		else
			echo -e "${e} ${s} \033[1;31mFAILED\033[0m"
			echo "expected: '${c}'"
			echo "actual  : '${t}'"
			exit -1;
		fi

		sleep 10;
	done

	sleep 60;
done
