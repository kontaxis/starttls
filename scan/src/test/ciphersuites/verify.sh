#!/bin/bash

# This script makes sure that ciphersuites.h adheres to the RFCs
# in terms of valid ciphersuites. test.c will print the cipher suites
# present in ciphersuites.h for a given version of SSL/TLS and the
# respective RFC will be downloaded and compared against the program's
# output. Keep in mind that we are grep-ing the RFC so false positives
# are expected.
# 
# kontaxis 2014-10-06

function test_spec {
	# test name
	name=$1
	# spec url
	spec=$2
	# return value
	local r=255;
	# test result
	local x="UNKNOWN ERROR";

	if [ "${name}" == "" ] || [ "${spec}" == "" ]; then
		return $r;
	fi

	echo -en "- TESTING \033[1;34m${name}\033[0m using ${spec} "
	
	# build
	x=`gcc -Wall -D${name} test.c -o test`;
	r=$?

	if [ "$r" != "0" ]; then
		echo -e "\033[1;31mFAILED\033[0m";
		echo -e "\033[1;35m$x\033[0m";
		return $r;
	fi

	# run
	x=`./test 2>&1`
	r=$?

	if [ "$r" != "0" ]; then
		echo -e "\033[1;31mFAILED\033[0m";
		echo -e "\033[1;35m$x\033[0m";
		return $r;
	fi

	# extract cipher suits from output
	if [ "${name}" == "__SSL_3_0__" ]; then
		echo "$x" | egrep -v "^ProtocolVersion" | sed s/"[ ]*"//g | sed s/"TLS"/"SSL"/g > test_${name}
	elif [ "${name}" == "__TLS_1_1__" ]; then
		echo "$x" | egrep -v "^ProtocolVersion" | sed s/"[ ]*"//g | sort > test_${name}
	else
		echo "$x" | egrep -v "^ProtocolVersion" | sed s/"[ ]*"//g | sort > test_${name}
	fi

	# get spec
	x=`curl "${spec}" --stderr -`
	r=$?

	if [ "$r" != "0" ]; then
		echo -e "\033[1;31mFAILED\033[0m";
		echo -e "\033[1;35m$x\033[0m";
		return $r;
	fi

	# extract cipher suites from spec
	if [ "${name}" == "__SSL_3_0__" ]; then
		echo "$x" | egrep "CipherSuite[ ]+SSL" | sed s/"[ ]*"//g | sed s/"0X"/"0x"/g > spec_${name}
	elif [ "${name}" == "__TLS_1_1__" ]; then
		echo "$x" | egrep "CipherSuite[ ]+TLS" | sed s/"[ ]*"//g | grep -v EXPORT | sed s/":\$"/";"/g | sort > spec_${name}
	elif [ "${name}" == "__RFC4492__" ] || \
			 [ "${name}" == "__RFC5054__" ] || \
			 [ "${name}" == "__RFC5288__" ] || \
			 [ "${name}" == "__RFC5289__" ] || \
			 [ "${name}" == "__RFC7027__" ]; then
		echo "$x" | egrep "CipherSuite[ ]+TLS" | sed s/"[ ]*"//g | sed s/"}\$"/"};"/g | sort | uniq > spec_${name}
	elif [ "${name}" == "__RFC5932__" ]; then
		echo "$x" | egrep "CipherSuite[ ]+TLS" | sed s/"[ ]*"//g | sed s/":\$"/";"/g | sort | uniq > spec_${name}
	else
		echo "$x" | egrep "CipherSuite[ ]+TLS" | sed s/"[ ]*"//g | sort > spec_${name}	
	fi

	# compare gainst spec
	x=`diff test_${name} spec_${name} 2>&1`;
	r=$?

	if [ "$r" != "0" ]; then
		echo -e "\033[1;31mFAILED\033[0m";
		echo -e "\033[1;35m$x\033[0m";
	else
		echo -e "\033[1;32mSUCCEEDED\033[0m";
	fi
	
	return $r;
}


test_spec "__SSL_3_0__" "https://www.ietf.org/rfc/rfc6101.txt"
test_spec "__TLS_1_0__" "https://www.ietf.org/rfc/rfc2246.txt"
test_spec "__RFC2712__" "https://www.ietf.org/rfc/rfc2712.txt"
test_spec "__RFC3268__" "https://www.ietf.org/rfc/rfc3268.txt"
test_spec "__DFTXP56__" "https://tools.ietf.org/id/draft-ietf-tls-56-bit-ciphersuites-01.txt"
test_spec "__RFC4132__" "https://www.ietf.org/rfc/rfc4132.txt"
test_spec "__RFC4162__" "https://www.ietf.org/rfc/rfc4162.txt"
test_spec "__RFC4279__" "https://www.ietf.org/rfc/rfc4279.txt"
test_spec "__TLS_1_1__" "https://www.ietf.org/rfc/rfc4346.txt"
test_spec "__RFC4492__" "https://www.ietf.org/rfc/rfc4492.txt"
test_spec "__RFC5054__" "https://www.ietf.org/rfc/rfc5054.txt"
test_spec "__TLS_1_2__" "https://www.ietf.org/rfc/rfc5246.txt"
test_spec "__RFC5288__" "https://www.ietf.org/rfc/rfc5288.txt"
test_spec "__RFC5289__" "https://www.ietf.org/rfc/rfc5289.txt"
test_spec "__RFC5932__" "https://www.ietf.org/rfc/rfc5932.txt"
test_spec "__RFC7027__" "https://www.ietf.org/rfc/rfc4492.txt"
