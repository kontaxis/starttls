#!/bin/bash

if [ ! -e openssl-1.0.1j ]; then
	curl https://www.openssl.org/source/openssl-1.0.1j.tar.gz | tar zxvf -
	cd openssl-1.0.1j && ./config --with-krb5-flavor=MIT && make && cd ../ && \
		export PATH="openssl-1.0.1j/apps:$PATH"
fi

function test_openssl {

	target=$1

	if [ "$target" == "ssl3" ]; then
		openssl_codes=`openssl ciphers -V 'ALL:COMPLEMENTOFALL' | grep SSLv3 | awk '{print $1}' | sort`
	elif [ "$target" == "tls12" ]; then
		openssl_codes=`openssl ciphers -V 'ALL:COMPLEMENTOFALL' | grep TLSv1.2 | awk '{print $1}' | sort`
	else
		openssl_codes=`openssl ciphers -V 'ALL:COMPLEMENTOFALL' | grep -v SSLv2 | awk '{print $1}' | sort`
	fi

	echo "($target) OpenSSL returned suites : `echo "${openssl_codes}" | wc -l`"

	if [ "$target" != "" ]; then
		starttls_codes=`../../../bin/smtp_${target} -l |& awk '{print $6}' | sort`
	else
		starttls_codes=`../../../bin/smtp_tls12_god -l |& awk '{print $6}' | sort`
	fi

	echo "($target) startTLS returned suites: `echo "${starttls_codes}" | wc -l`"

	for c in ${openssl_codes}; do
		t=`echo "${starttls_codes}" | grep $c`;
		if [ "$t" == "" ]; then
			echo "> OpenSSL $c missing from starttls ($target)";
		fi
	done

	for c in ${starttls_codes}; do
		t=`echo "${openssl_codes}" | grep $c`;
		if [ "$t" == "" ]; then
			echo "< starttls $c missing from openSSL ($target)";
		fi
	done
}

# https://www.openssl.org/docs/apps/ciphers.html

# 0x00
# 0x0B - 0x10 0_NOT_IMPLEMENTED
# 0x1C - 0x1E 0_FORTEZZA_DISABLED
test_openssl "ssl3" \
|& egrep -v "0x00,0x0[0|B-F] missing from openSSL" \
|& egrep -v "0x00,0x1[0|C-E] missing from openSSL"

# 0x00
# 0x0B - 0x10 0_NOT_IMPLEMENTED
# 0x1C - 0x1E 0_FORTEZZA_DISABLED
# 0x30 - 0x31 0_
# 0x36        0_
# 0x37        0_NOT_IMPLEMENTED
# 0x3E - 0x3F 0_NOT_IMPLEMENTED
# 0x42 - 0x43 0_NOT_IMPLEMENTED
# 0x60 - 0x61 0_EXPERIMENTAL_DISABLED
# 0x62 - 0x66 0_EXPERIMENTAL
# 0x68 - 0x69 0_NOT_IMPLEMENTED
# 0x85 - 0x86 0_NOT_IMPLEMENTED
# 0x8E - 0x8F NO_REFERENCE*
# 0x90 - 0x95 NO_REFERENCE*
# 0x97 - 0x98 0_NOT_IMPLEMENTED
# 0xA0 - 0xA1 0_
# 0xA4 - 0xA5 0_
# 0xBA - 0xBF NO_REFERENCE*
# 0xC0 - 0xC5 NO_REFERENCE*
test_openssl "tls12" \
|& egrep -v "0x00,0x0[0|B-F] missing from openSSL" \
|& egrep -v "0x00,0x1[0|C-E] missing from openSSL" \
|& egrep -v "0x00,0x3[0-1|6|7|E-F] missing from openSSL" \
|& egrep -v "0x00,0x4[2-3] missing from openSSL" \
|& egrep -v "0x00,0x6[0-1|2-6|8-9] missing from openSSL" \
|& egrep -v "0x00,0x8[5-6] missing from openSSL" \
|& egrep -v "0x00,0x8[E-F] missing from openSSL" \
|& egrep -v "0x00,0x9[0-5] missing from openSSL" \
|& egrep -v "0x00,0x9[7-8] missing from openSSL" \
|& egrep -v "0x00,0xA[0-1] missing from openSSL" \
|& egrep -v "0x00,0xA[4-5] missing from openSSL" \
|& egrep -v "0x00,0xB[A-F] missing from openSSL" \
|& egrep -v "0x00,0xC[0-5] missing from openSSL"

# 0x00
# 0x0B - 0x10 0_NOT_IMPLEMENTED
# 0x1C - 0x1E 0_FORTEZZA_DISABLED
# 0x30 - 0x31 0_
# 0x36        0_
# 0x37        0_NOT_IMPLEMENTED
# 0x3E - 0x3F 0_NOT_IMPLEMENTED
# 0x42 - 0x43 0_NOT_IMPLEMENTED
# 0x60 - 0x61 0_EXPERIMENTAL_DISABLED
# 0x62 - 0x66 0_EXPERIMENTAL
# 0x68 - 0x69 0_NOT_IMPLEMENTED
# 0x85 - 0x86 0_NOT_IMPLEMENTED
# 0x8E - 0x8F NO_REFERENCE*
# 0x90 - 0x95 NO_REFERENCE*
# 0x97 - 0x98 0_NOT_IMPLEMENTED
# 0xA0 - 0xA1 0_
# 0xA4 - 0xA5 0_
# 0xBA - 0xBF NO_REFERENCE*
# 0xC0 - 0xC5 NO_REFERENCE*
#
# *: Overall it seems non-ephemeral DH is not implemented
# so lack of any reference could be attributed to that.
# Usually such suites are listed, disabled and a note is
# made to the fact.
test_openssl "" \
|& egrep -v "0x00,0x0[0|B-F] missing from openSSL" \
|& egrep -v "0x00,0x1[0|C-E] missing from openSSL" \
|& egrep -v "0x00,0x3[0-1|6|7|E-F] missing from openSSL" \
|& egrep -v "0x00,0x4[2-3] missing from openSSL" \
|& egrep -v "0x00,0x6[0-1|2-6|8-9] missing from openSSL" \
|& egrep -v "0x00,0x8[5-6] missing from openSSL" \
|& egrep -v "0x00,0x8[E-F] missing from openSSL" \
|& egrep -v "0x00,0x9[0-5] missing from openSSL" \
|& egrep -v "0x00,0x9[7-8] missing from openSSL" \
|& egrep -v "0x00,0xA[0-1] missing from openSSL" \
|& egrep -v "0x00,0xA[4-5] missing from openSSL" \
|& egrep -v "0x00,0xB[A-F] missing from openSSL" \
|& egrep -v "0x00,0xC[0-5] missing from openSSL"
