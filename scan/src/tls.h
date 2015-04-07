#ifndef __TLS_H__
#define __TLS_H__

/* kontaxis 2014-10-06 */

#include "ciphersuites.h"

/* converts 16 bits in host byte order to 16 bits in network byte order */
#define h16ton16(n) \
((uint16_t) (((uint16_t) n) << 8) | (uint16_t) (((uint16_t) n) >> 8))

#define n16toh16(buf) h16ton16(buf)

/* converts 24 bits in network byte order to 32 bits in host byte order */
#define n24toh32(buf) \
(((uint32_t) *(((uint8_t*)buf) + 0)) << 16 |\
 ((uint32_t) *(((uint8_t*)buf) + 1)) <<  8 |\
 ((uint32_t) *(((uint8_t*)buf) + 2)) <<  0)

/* convers 24 bits in host byte order to 32 bits in network byte order */
#define h24ton24(n,buf) \
{\
*(((uint8_t*)buf) + 0) = (uint8_t) (((uint32_t)n) >> 16);\
*(((uint8_t*)buf) + 1) = (uint8_t) (((uint32_t)n) >>  8);\
*(((uint8_t*)buf) + 2) = (uint8_t) (((uint32_t)n) >>  0);\
}


/*
 * References:
 * - https://tools.ietf.org/html/rfc5246 TLS 1.2
 * - https://tools.ietf.org/html/rfc4346 TLS 1.1
 * - https://tools.ietf.org/html/rfc2246 TLS 1.0
 * - https://tools.ietf.org/html/rfc6101 SSL 3.0
 */

/* ContentType */
#define SSL3_RT_CHANGE_CIPHER_SPEC 20
#define SSL3_RT_ALERT              21
#define SSL3_RT_HANDSHAKE          22 /* 0x16 */
#define SSL3_RT_APPLICATION_DATA   23

struct __attribute__((__packed__))
{
	/* TLSPlaintext 5 bytes */
	uint8_t  TLSPlaintext__type; /* ContentType */
	uint8_t  TLSPlaintext__versionMajor;
	uint8_t  TLSPlaintext__versionMinor;
	uint16_t TLSPlaintext__length;
} TLSPlaintext_header =
{
	.TLSPlaintext__versionMajor = PROTOCOLMAJOR,
	.TLSPlaintext__versionMinor = PROTOCOLMINOR
};

/* AlertLevel */
#define SSL3_AL_WARNING 1
#define SSL3_AL_FATAL   2

/* AlertDescription */
#define SSL3_AD_CLOSE_NOTIFY        0
#define SSL3_AD_UNEXPECTED_MESSAGE 10
#define SSL3_AD_BAD_RECORD_MAC     20

struct __attribute__((__packed__))
{
	/* Alert 2 bytes */
	uint8_t Alert__level; /* AlertLevel */
	uint8_t Alert__description; /* AlertDescription */
} TLSAlert_header;

/* HandshakeType */
#define SSL3_MT_HELLO_REQUEST        0
#define SSL3_MT_CLIENT_HELLO         1
#define SSL3_MT_SERVER_HELLO         2
#define SSL3_MT_CERTIFICATE         11
#define SSL3_MT_SERVER_KEY_EXCHANGE 12
#define SSL3_MT_CERTIFICATE_REQUEST 13
#define SSL3_MT_SERVER_DONE         14
#define SSL3_MT_CERTIFICATE_VERIFY  15
#define SSL3_MT_CLIENT_KEY_EXCHANGE 16
#define SSL3_MT_FINISHED            20

struct __attribute__((__packed__))
{
	/* Handshake 4 bytes */
	uint8_t  Handshake__type; /* HandshakeType */
	uint8_t  Handshake__length[3];
} TLSHandshake_header;

/* ClientHello */

struct __attribute__((__packed__))
{
	uint8_t  client_version_major;
	uint8_t  client_version_minor;
	uint32_t random_gmt_unix_time;
	uint8_t  random_random_bytes[28];
} client_hello_intro =
{
	.client_version_major = PROTOCOLMAJOR,
	.client_version_minor = PROTOCOLMINOR
};

struct __attribute__((__packed__))
{
	uint8_t  session_id_length;
	uint8_t  session_id[32];
} client_hello_session =
{
	.session_id_length = 0
};

struct __attribute__((__packed__))
{
	uint16_t cipher_suites_length;
	uint16_t cipher_suites[(0xFFFF - 1)/sizeof(uint16_t)];
} client_hello_ciphersuites =
{
	.cipher_suites_length = 0x0200,
	.cipher_suites[0] = h16ton16(CIPHERSUITEMANDATORY)
};

struct __attribute__((__packed__))
{
	uint8_t compression_methods_length;
	uint8_t compression_methods[0xFF];
} client_hello_compression =
{
	.compression_methods_length = 0x1,
	.compression_methods[0] = 0x0
};

/* Smallest ClientHello */

struct __attribute__((__packed__))
{
	/* ClientHello 41 bytes */
	uint8_t  client_version_major;
	uint8_t  client_version_minor;
	uint32_t random_gmt_unix_time;
	uint8_t  random_random_bytes[28];
	uint8_t  session_id_length;
	uint16_t cipher_suites_length;
	uint16_t cipher_suites[1];
	uint8_t  compression_methods_length;
	uint8_t  compression_methods[1];
} client_hello_min =
{
	.session_id_length = 0,
	.cipher_suites_length = 0x0200,
	.compression_methods_length = 0x1
};

/* ServerHello */

struct __attribute__((__packed__))
{
	uint8_t  server_version_major;
	uint8_t  server_version_minor;
	uint32_t random_gmt_unix_time;
	uint8_t  random_random_bytes[28];
} server_hello_intro;

struct __attribute__((__packed__))
{
	uint8_t  session_id_length;
	uint8_t  session_id[32];
} server_hello_session;

struct __attribute__((__packed__))
{
	uint16_t cipher_suite;
} server_hello_ciphersuite;

struct __attribute__((__packed__))
{
	uint8_t compression_method;
} server_hello_compression;

/* Smallest ServerHello */

struct __attribute__((__packed__))
{
	/* ServerHello 38 bytes */
	uint8_t  server_version_major;
	uint8_t  server_version_minor;
	uint32_t random_gmt_unix_time;
	uint8_t  random_random_bytes[28];
	uint8_t  session_id_length;
	uint16_t cipher_suite;
	uint8_t  compression_method;
} server_hello_min =
{
	.session_id_length = 0
};

/* Certificate */

struct __attribute__((__packed__))
{
	uint8_t certificate_length[3];
	uint8_t certificate[0xFFFFFF];
} asn1certificate;

/* Smallest ASN1 Certificate */

struct __attribute__((__packed__))
{
	uint8_t certificate_length[3];
	uint8_t certificate[1];
} asn1certificate_min =
{
	.certificate_length = {0x00, 0x00, 0x01}
};

struct __attribute__((__packed__))
{
	uint8_t certificate_list_length[3];
	uint8_t certificate_list[0xFFFFFF];
} certificate;

/* Smallest Certificate */

struct __attribute__((__packed__))
{
	uint8_t certificate_list_length[3];
} certificate_min =
{
	.certificate_list_length = {0x00, 0x00, 0x00}
};

/* Extension */

struct __attribute__((__packed__))
{
	uint16_t extensions_length;
	uint8_t  extensions[0xFFFF];
} extensions;


/* Auxiliary decoding functions and utilities */

char *TLSContentType(uint8_t n)
{
	switch (n) {
		/* 20*/
		case SSL3_RT_CHANGE_CIPHER_SPEC:
			return "change_cipher_spec";
		/* 21 */
		case SSL3_RT_ALERT:
			return "alert";
		/* 22 */
		case SSL3_RT_HANDSHAKE:
			return "handshake";
		/* 23 */
		case SSL3_RT_APPLICATION_DATA:
			return "application_data";
		default:
			return "UNKNOWN";
	}

	return "";
}

char *AlertLevel(uint8_t n)
{
	switch(n) {
		/* 1 */
		case SSL3_AL_WARNING:
			return "warning";
		/* 2 */
		case SSL3_AL_FATAL:
			return "fatal";
		default:
			return "UNKNOWN";
	}

	return "";
}

char *AlertDescription(uint8_t n)
{
	switch(n) {
		/* 0 */
		case SSL3_AD_CLOSE_NOTIFY:
			return "close_notify";
		/* 10 */
		case SSL3_AD_UNEXPECTED_MESSAGE:
			return "unexpected_message";
		/* 20 */
		case SSL3_AD_BAD_RECORD_MAC:
			return "bad_record_mac";
		case 21:
			return "decryption_failed_RESERVED";
		case 22:
			return "record_overflow";
		case 30:
			return "decompression_failure";
		case 40:
			return "handshake_failure";
		case 41:
			return "no_certificate_RESERVED";
		case 42:
			return "bad_certificate";
		case 43:
			return "unsupported_certificate";
		case 44:
			return "certificate_revoked";
		case 45:
			return "certificate_expired";
		case 46:
			return "certificate_unknown";
		case 47:
			return "illegal_parameter";
		case 48:
			return "unknown_ca";
		case 49:
			return "access_denied";
		case 50:
			return "decode_error";
		case 51:
			return "decrypt_error";
		default:
			return "UNKNOWN";
	}

	return "";
}

char *TLSHandshakeType(uint8_t n)
{
	switch(n) {
		/* 0 */
		case SSL3_MT_HELLO_REQUEST:
			return "hello_request";
		/* 1 */
		case SSL3_MT_CLIENT_HELLO:
			return "client_hello";
		/* 2 */
		case SSL3_MT_SERVER_HELLO:
			return "server_hello";
		/* 11 */
		case SSL3_MT_CERTIFICATE:
			return "certificate";
		/* 12 */
		case SSL3_MT_SERVER_KEY_EXCHANGE:
			return "server_key_exchange";
		/* 13 */
		case SSL3_MT_CERTIFICATE_REQUEST:
			return "certificate_request";
		/* 14 */
		case SSL3_MT_SERVER_DONE:
			return "server_hello_done";
		/* 15 */
		case SSL3_MT_CERTIFICATE_VERIFY:
			return "certificate_verify";
		/* 16 */
		case SSL3_MT_CLIENT_KEY_EXCHANGE:
			return "client_key_exchange";
		/* 20 */
		case SSL3_MT_FINISHED:
			return "finished";
		default:
			return "UNKNOWN";
	}

	return "";
}

#endif
