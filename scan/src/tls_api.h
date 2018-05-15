#ifndef __TLS_API_H__
#define __TLS_API_H__

/* kontaxis 2014-10-06 */

#include <stdint.h>

/* Initialization. Must be called before anything else.
 * tls_live() and tls_replay() will refuse to run otherwise. */
int tls_init (void);

/* Configuration. Mandatory. Sets input descriptor
 * (socket in live mode, file in replay). */
int tls_set_in  (int fd);
/* Configuration. Optional. Sets output descriptor
 * (dump file). If not set, default-named files are
 * generated in the current directory. */
int tls_set_out (int fd);
/* Configuration. Optional. Sets ciphersuites to be used.
 * If not set, the RFC mandatory suite will be used. */
int tls_set_suites (uint16_t *suites, uint16_t suite_count);
/* Configuration. Optional. Set a callback function to be invoked
 * for each certificate of a Certificate handshake message. */
int tls_set_callback_handshake_certificate (int (*handler)(
	uint8_t *certificate, uint32_t certificate_length));
/* Configuration. Optional. Set a callback function to be invoked
 * for each ServerKeyExchange handshake message. It is the responsibility
 * of the function's implementation to correctly parse the message structure
 * based on the key exchange algorithm.
 */
struct __attribute__((__packed__)) ServerDHParams {
	uint16_t dh_p_length;
	uint8_t  dh_p[0xFFFF];
	uint16_t dh_g_length;
	uint8_t  dh_g[0xFFFF];
	uint16_t dh_Ys_length;
	uint8_t  dh_Ys[0xFFFF];
};
struct __attribute__((__packed__)) Signature {
	uint8_t  algorithm_hash;
	uint8_t  algorithm_signature;
	uint16_t signature_length;
	uint8_t  signature[0xFFFF];
};
#define SERVER_KEYEXCHANGE_UNKNOWN  0x0
#define SERVER_KEYEXCHANGE_DHPARAMS 0x7
struct __attribute__((__packed__)) ServerKeyExchange_DHparams {
  struct ServerDHParams  *params;
};
#define SERVER_KEYEXCHANGE_DHPARAMS_SIGNATURE (\
	0x3 | SERVER_KEYEXCHANGE_DHPARAMS)
struct __attribute__((__packed__)) ServerKeyExchange_DHparams_signature {
  struct ServerDHParams  *params;
  struct DigitallySigned *signed_params;
};
int tls_set_callback_handshake_server_key_exchange (int (*handler)(
	uint8_t *ServerKeyExchange, uint32_t ServerKeyExchangeType));


/* Execution. Live mode. Read from tls_in (logically a socket) and
 * write to tls_out. tls_in must be set using tls_set_in().
 * tls_out is set internally. */
int tls_live   (void);
/* Execution. Replay mode. Read from tls_in (logically a file produced
 * using tls_out in live mode). tls_out is not set. The purpose of replay
 * mode is to allow callbacks to work on the captured trace file. */
int tls_replay (void);


/* Information. Return the current error code. Will be 0 if all is well. */
int tls_error (void);


/* Information. Prints the suites available for the currrent
 * SSL/TLS protocol in stderr. */
void tls_print_suites  (void);

/* Information. Return an array with the RFC suite numbers for the current
 * SSL/TLS protocol. Can be used in repeated calls to tls_set_suite() to
 * scan a target for supported suites. */
uint16_t* tls_suites (void);
/* Information. Return the number of suites available for the current
 * SSL/TLS protocol. */
uint16_t  tls_suite_count (void);

/* Information. Given the RFC number of a ciphersuite return a string
 * with its RFC name. */
const char * tls_suite_name (uint16_t n);


/* Information. Prints SSL/TLS protocol version in stderr. */
void tls_print_version (void);

/* Flags indicating that a particular statistic is valid. */

/* tls_version_major(), tls_version_minor() */
#define STAT_TLS_VERSION    (0x1 << 0)
/* tls_server_version_major(), tls_server_version_minor() */
#define STAT_SERVER_VERSION (0x1 << 1)
/* tls_server_suite() */
#define STAT_SERVER_SUITE   (0x1 << 2)

#define TLS_VERSION_VALID (tls_stat_flags() & STAT_TLS_VERSION)
#define TLS_SERVER_VERSION_VALID (tls_stat_flags() & STAT_SERVER_VERSION)
#define TLS_SERVER_SUITE_VALID (tls_stat_flags() & STAT_SERVER_SUITE)

uint8_t tls_stat_flags (void);

/* Information. Return the current SSL/TLS protocol major version number. */
uint8_t tls_suite_version_major (void);
/* Information. Return the current SSL/TLS protocol minor version number. */
uint8_t tls_suite_version_minor (void);

/* Information. Return the server's reported SSL/TLS protocol major version
 * number. This reflects the value in the last TLS record processed. */
uint8_t tls_version_major (void);
/* Information. Return the server's reported SSL/TLS protocol minor version
 * number. This reflects the value in the last TLS record processed. */
uint8_t tls_version_minor (void);

/* Information. Return the server's reported SSL/TLS protocol major version
 * number. This reflects the value in the last ServerHello processed. */
uint8_t tls_server_version_major (void);
/* Information. Return the server's reported SSL/TLS protocol minor version
 * number. This reflects the value in the last ServerHello processed. */
uint8_t tls_server_version_minor (void);

/* Information. Return the server's supported ciphersuite.
 * This reflects the value in the last ServerHello processed. */
uint16_t tls_server_suite (void);

#define TLS_ERROR_RESERVED 0
#define TLS_ERROR_NONE     1 /* Success */
#define TLS_ERROR_NOOP     2
#define TLS_ERROR_UNKNOWN  3
#define TLS_ERROR_ALERT    4

#endif
