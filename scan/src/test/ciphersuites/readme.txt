# This script makes sure that ciphersuites.h adheres to the RFCs
# in terms of valid ciphersuites. test.c will print the cipher suites
# present in ciphersuites.h for a given version of SSL/TLS and the
# respective RFC will be downloaded and compared against the program's
# output. Keep in mind that we are grep-ing the RFC so false positives
# are expected.
#
# kontaxis 2014-10-06

__DFTXP56__
(https://tools.ietf.org/id/draft-ietf-tls-56-bit-ciphersuites-01.txt)
does NOT include the following suites (but openSSL does):
< CipherSuiteTLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5={0x00,0x61};
< CipherSuiteTLS_RSA_EXPORT1024_WITH_RC4_56_MD5={0x00,0x60};
