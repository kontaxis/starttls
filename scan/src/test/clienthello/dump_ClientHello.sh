#!/bin/bash

file=$1;

if [ "${file}" == "" ]; then
	exit -1;
fi


# TLS Plaintext Type (1)
offset=1
echo "TLS_Plaintext_Type: 0x`head -c ${offset} $1 | tail -c 1 | xxd -u -ps`"
>&2 echo "0x`head -c ${offset} $1 | tail -c 1 | xxd -u -ps` "

# TLS Plaintext Version Major (1)
let offset=offset+1;
echo "TLS_Plaintext_Version_Major: 0x`head -c ${offset} $1 | tail -c 1 | xxd -u -ps`"
>&2 echo "0x`head -c ${offset} $1 | tail -c 1 | xxd -u -ps` "

# TLS Plaintext Version Minor (1)
let offset=offset+1;
echo "TLS_Plaintext_Version_Minor: 0x`head -c ${offset} $1 | tail -c 1 | xxd -u -ps`"
>&2 echo "0x`head -c ${offset} $1 | tail -c 1 | xxd -u -ps` "

# TLS Plaintext Length (2)
let offset=offset+2;
echo "TLS_Plaintext_Length: 0x`head -c ${offset} $1 | tail -c 2 | xxd -u -ps`"
>&2 echo "0x`head -c ${offset} $1 | tail -c 2 | xxd -u -ps` "

echo ${offset}


# TLS Handshake Type (1)
let offset=offset+1;
echo "TLS_Handshake_Type: 0x`head -c ${offset} $1 | tail -c 1 | xxd -u -ps`"
>&2 echo "0x`head -c ${offset} $1 | tail -c 1 | xxd -u -ps` "

# TLS Handshake Length (3)
let offset=offset+3;
echo "TLS_Handshake_Length: 0x`head -c ${offset} $1 | tail -c 3 | xxd -u -ps`"
>&2 echo "0x`head -c ${offset} $1 | tail -c 3 | xxd -u -ps` "

echo ${offset}


# TLS Handshake ClientHello Version Major (1)
let offset=offset+1;
echo "TLS_ClientHello_Version_Major: 0x`head -c ${offset} $1 | tail -c 1 | xxd -u -ps`"
>&2 echo "0x`head -c ${offset} $1 | tail -c 1 | xxd -u -ps` "

# TLS Handshake ClientHello Version Minor (1)
let offset=offset+1;
echo "TLS_ClientHello_Version_Minor: 0x`head -c ${offset} $1 | tail -c 1 | xxd -u -ps`"
>&2 echo "0x`head -c ${offset} $1 | tail -c 1 | xxd -u -ps` "

# TLS Handshake ClientHello Random Unix Time (4)
let offset=offset+4;
echo "TLS_ClientHello_Random_Unix_Time: 0x`head -c ${offset} $1 | tail -c 4 | xxd -u -ps`"
>&2 echo "0x`head -c ${offset} $1 | tail -c 4 | xxd -u -ps` "

# TLS Handshake ClientHello Random Bytes (28)
let offset=offset+28;
echo "TLS_ClientHello_Random_Bytes: 0x`head -c ${offset} $1 | tail -c 28 | xxd -u -ps`"
>&2 echo "0x`head -c ${offset} $1 | tail -c 28 | xxd -u -ps` "

# TLS Handshake ClientHello Session ID length (1)
let offset=offset+1;
echo "TLS_ClientHello_SessionID_length: 0x`head -c ${offset} $1 | tail -c 1 | xxd -u -ps`"
>&2 echo "0x`head -c ${offset} $1 | tail -c 1 | xxd -u -ps` "

# TLS Handshake ClientHello Ciphersuites length (2)
let offset=offset+2;
echo "TLS_ClientHello_Ciphersuites_length: 0x`head -c ${offset} $1 | tail -c 2 | xxd -u -ps`"
>&2 echo "0x`head -c ${offset} $1 | tail -c 2 | xxd -u -ps` "

# TLS Handshake ClientHello Ciphersuites (2)
let offset=offset+2;
echo "TLS_ClientHello_Ciphersuites: 0x`head -c ${offset} $1 | tail -c 2 | xxd -u -ps`"
>&2 echo "0x`head -c ${offset} $1 | tail -c 2 | xxd -u -ps` "

# TLS Handshake ClientHello Compression methods length (1)
let offset=offset+1;
echo "TLS_ClientHello_Compression_methods_length: 0x`head -c ${offset} $1 | tail -c 1 | xxd -u -ps`"
>&2 echo "0x`head -c ${offset} $1 | tail -c 1 | xxd -u -ps` "

# TLS Handshake ClientHello Compression methods (1)
let offset=offset+1;
echo "TLS_ClientHello_Compression_methods: 0x`head -c ${offset} $1 | tail -c 1 | xxd -u -ps`"
>&2 echo "0x`head -c ${offset} $1 | tail -c 1 | xxd -u -ps` "

echo ${offset}
