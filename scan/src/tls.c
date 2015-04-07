/* kontaxis 2014-10-06 */

#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>

#include "tls.h"
#include "ciphersuites.h"

#include "aux.h"

#include "tls_api.h"

/* generic socket read/write buffers are this big */
#define BUF_SIZE 0xFFFF

/* input socket descriptor.
 *
 * in live mode this is used also for writing.
 * in replay mode this is used only for reading.
 */
int tls_in;

/* output socket descriptor.
 *
 * in live mode this is used to dump the TLS conversation to a file.
 * in replay mode this is not used.
 */
int tls_out;

/* Callback functions. Indexed by [ContentType]HandshakeType] */
int (*tls_callbacks[0xFF][0xFF])(uint8_t *, uint32_t);

/* RFC number of the ciphersuites to be used. tls_set_suites() updates
 * this array. Otherwise the default (mandatory) suite for the current
 * SSL/TLS protocol is used. */
uint16_t opt_ciphersuites[0xFFFF + 1];
uint16_t opt_ciphersuite_count;

/* statistics */
uint8_t TLSPlaintext__versionMajor;
uint8_t TLSPlaintext__versionMinor;
uint8_t server_version_major;
uint8_t server_version_minor;
uint16_t server_suite;

/* Flags indicating that a particular statistic is valid. */
uint8_t stat_flags;

/* status code */
unsigned int error_tls;

/* Flag indicating whether this code has been safely initialized. */
unsigned int tls_initialized = 0;



/*
 * process a TLS Handshake ClientHello message
 */
int process_TLS_Handshake_ClientHello()
{
#if __DEBUG__
	unsigned int i;
#endif
	unsigned int r;

	unsigned int must_read_bytes;

#if __DEBUG__
	time_t t;
	struct tm *ts;
	char time_buf[80];
#endif

	assert(n24toh32(TLSHandshake_header.Handshake__length) >=
		sizeof(client_hello_min));

	must_read_bytes = n24toh32(TLSHandshake_header.Handshake__length);

	/* Read up to the session ID length byte. Since the session ID
   * is of variable length we need to figure out how much to read as such. */

	if (read_bytes(tls_in, &client_hello_intro,
		sizeof(client_hello_intro)) <= 0) {
		return -1;
	}
	must_read_bytes -= sizeof(client_hello_intro);

#if __DEBUG__
	fprintf(stderr, "TLS ClientHello Version: %s (0x%02x%02x)\n",
		PROTOCOL_TXT(client_hello_intro.client_version_minor),
		client_hello_intro.client_version_major,
		client_hello_intro.client_version_minor);

	t = ntohl(client_hello_intro.random_gmt_unix_time);
	ts = localtime(&t);
	if (strftime(time_buf, sizeof(time_buf), "%b %d, %Y %H:%M:%S %Z", ts)) {
		fprintf(stderr, "TLS ClientHello Random gmt_unix_time: %s (%u)\n",
			time_buf, ntohl(client_hello_intro.random_gmt_unix_time));
	}

	fprintf(stderr, "TLS ClientHello Random random_bytes: ");
	for (i = 0; i < 28; i++)
		fprintf(stderr, "%02x", client_hello_intro.random_random_bytes[i]);
	fprintf(stderr, "\n");
#endif

	/* log */
	if (tls_out != -1) {
		r = write(tls_out, &client_hello_intro, sizeof(client_hello_intro));
		if (r == 0 || r == -1) {
			perror("write");
			return -1;
		}
	}

	if (read_bytes(tls_in, &client_hello_session.session_id_length,
		sizeof(client_hello_session.session_id_length)) <= 0) {
		return -1;
	}
	must_read_bytes -= sizeof(client_hello_session.session_id_length);

#if __DEBUG__
	fprintf(stderr, "TLS ClientHello Session ID Length: %u\n",
		client_hello_session.session_id_length);
#endif

	/* log */
	if (tls_out != -1) {
		r = write(tls_out, &client_hello_session.session_id_length,
			sizeof(client_hello_session.session_id_length));
		if (r == 0 || r == -1) {
			perror("write");
			return -1;
		}
	}

  /* Now we know we must read session_id_length bytes */

	assert(client_hello_session.session_id_length <=
		sizeof(client_hello_session.session_id));

	if (client_hello_session.session_id_length) {
		if (read_bytes(tls_in, client_hello_session.session_id,
			client_hello_session.session_id_length) <= 0) {
			return -1;
		}
		must_read_bytes -= client_hello_session.session_id_length;
	}

#if __DEBUG__
	for (i = 0; i < client_hello_session.session_id_length; i++) {
		if (i == 0) {
			fprintf(stderr, "TLS ClientHello Session ID: ");
		}
		fprintf(stderr, "%02x", client_hello_session.session_id[i]);
		if (i + 1 == client_hello_session.session_id_length) {
			fprintf(stderr, "\n");
		}
	}
#endif

	/* log */
	if (tls_out != -1) {
		if (client_hello_session.session_id_length) {
			r = write(tls_out, client_hello_session.session_id,
				client_hello_session.session_id_length);
			if (r == 0 || r == -1) {
				perror("write");
				return -1;
			}
		}
	}

	/* ciphersuites */

	if (read_bytes(tls_in, &client_hello_ciphersuites.cipher_suites_length,
		sizeof(client_hello_ciphersuites.cipher_suites_length)) <= 0) {
		return -1;
	}
	must_read_bytes -= sizeof(client_hello_ciphersuites.cipher_suites_length);

#if __DEBUG__
	fprintf(stderr, "TLS ClientHello Cipher Suites Length: %u\n",
		n16toh16(client_hello_ciphersuites.cipher_suites_length));
#endif

	/* log */
	if (tls_out != -1) {
		r = write(tls_out, &client_hello_ciphersuites.cipher_suites_length,
			sizeof(client_hello_ciphersuites.cipher_suites_length));
		if (r == 0 || r == -1) {
			perror("write");
			return -1;
		}
	}

	assert(n16toh16(client_hello_ciphersuites.cipher_suites_length) <=
		sizeof(client_hello_ciphersuites.cipher_suites));

	if (read_bytes(tls_in, client_hello_ciphersuites.cipher_suites,
		n16toh16(client_hello_ciphersuites.cipher_suites_length)) <= 0) {
		return -1;
	}
	must_read_bytes -= n16toh16(client_hello_ciphersuites.cipher_suites_length);

#if __DEBUG__
	/* length is in bytes */
	for (i = 0;
		i < n16toh16(client_hello_ciphersuites.cipher_suites_length) /
			sizeof(CipherSuite); i++) {
		fprintf(stderr, "TLS ClientHello Cipher Suite: %s (0x%04x)\n",
			CIPHER_TXT(n16toh16(client_hello_ciphersuites.cipher_suites[i])),
			n16toh16(client_hello_ciphersuites.cipher_suites[i]));
	}
#endif

	/* log */
	if (tls_out != -1) {
		r = write(tls_out, client_hello_ciphersuites.cipher_suites,
			n16toh16(client_hello_ciphersuites.cipher_suites_length));
		if (r == 0 || r == -1) {
			perror("write");
			return -1;
		}
	}

	/* compression */

	if (read_bytes(tls_in, &client_hello_compression.compression_methods_length,
		sizeof(client_hello_compression.compression_methods_length)) <= 0) {
		return -1;
	}
	must_read_bytes -=
		sizeof(client_hello_compression.compression_methods_length);

#if __DEBUG__
	fprintf(stderr, "TLS ClientHello Compression Methods Length: %u\n",
		client_hello_compression.compression_methods_length);
#endif

	/* log */
	if (tls_out != -1) {
		r = write(tls_out, &client_hello_compression.compression_methods_length,
			sizeof(client_hello_compression.compression_methods_length));
		if (r == 0 || r == -1) {
			perror("write");
			return -1;
		}
	}

	assert(client_hello_compression.compression_methods_length <=
		sizeof(client_hello_compression.compression_methods));

	if (read_bytes(tls_in, client_hello_compression.compression_methods,
		client_hello_compression.compression_methods_length) <= 0) {
		return -1;
	}
	must_read_bytes -= client_hello_compression.compression_methods_length;

#if __DEBUG__
	for (i = 0; i < client_hello_compression.compression_methods_length; i++) {
		fprintf(stderr, "TLS ClientHello Compression Method: %s (%u)\n",
			COMPRESSION_TXT(client_hello_compression.compression_methods[i]),
			client_hello_compression.compression_methods[i]);
	}
#endif

	/* log */
	if (tls_out != -1) {
		r = write(tls_out, client_hello_compression.compression_methods,
			client_hello_compression.compression_methods_length);
		if (r == 0 || r == -1) {
			perror("write");
			return -1;
		}
	}

	/* extensions */

	if (must_read_bytes > 0) {
		if (read_bytes(tls_in, &extensions.extensions_length,
			sizeof(extensions.extensions_length)) <= 0) {
			return -1;
		}
		must_read_bytes -= sizeof(extensions.extensions_length);

#if __DEBUG__
		fprintf(stderr, "TLS ClientHello Extensions Length: %u\n",
			n16toh16(extensions.extensions_length));
#endif

		/* log */
		if (tls_out != -1) {
			r = write(tls_out, &extensions.extensions_length,
				sizeof(extensions.extensions_length));
			if (r == 0 || r == -1) {
				perror("write");
				return -1;
			}
		}

		/* Now we know we must read extensions_length bytes */

		assert(n16toh16(extensions.extensions_length) <=
			sizeof(extensions.extensions));

		if (n16toh16(extensions.extensions_length)) {
			if (read_bytes(tls_in, extensions.extensions,
				n16toh16(extensions.extensions_length)) <= 0) {
				return -1;
			}
			must_read_bytes -= n16toh16(extensions.extensions_length);
		}

		/* log */
		if (tls_out != -1) {
			if (n16toh16(extensions.extensions_length)) {
				r = write(tls_out, extensions.extensions,
					n16toh16(extensions.extensions_length));
				if (r == 0 || r == -1) {
					perror("write");
					return -1;
				}
			}
		}
	}

	/* Make sure we've read *exactly* Handshake__length bytes */

	assert(must_read_bytes == 0);

	return 0;
}


int prepare_TLS_Handshake_ClientHello (void)
{
	uint16_t i;

	client_hello_intro.client_version_major = PROTOCOLMAJOR;
	client_hello_intro.client_version_minor = PROTOCOLMINOR;
	client_hello_intro.random_gmt_unix_time = 0;
	memset(client_hello_intro.random_random_bytes, 0,
		sizeof(client_hello_intro.random_random_bytes));

	client_hello_session.session_id_length = 0;

	for (i = 0; i < opt_ciphersuite_count &&
		i < (sizeof(client_hello_ciphersuites.cipher_suites)/
				sizeof(client_hello_ciphersuites.cipher_suites[0])); i++) {
		client_hello_ciphersuites.cipher_suites[i] = h16ton16(opt_ciphersuites[i]);
	}
	client_hello_ciphersuites.cipher_suites_length =
		h16ton16(i * sizeof(opt_ciphersuites[0]));

	client_hello_compression.compression_methods_length = 0x1;
	client_hello_compression.compression_methods[0] = 0x0;

	return 0;
}


/*
 * process a TLS Handshake ServerHello message
 */
int process_TLS_Handshake_ServerHello()
{
#if __DEBUG__
	unsigned int i;
#endif
	unsigned int r;

	unsigned int must_read_bytes;

#if __DEBUG__
	time_t t;
	struct tm *ts;
	char time_buf[80];
#endif

	assert(n24toh32(TLSHandshake_header.Handshake__length) >=
		sizeof(server_hello_min));

	must_read_bytes = n24toh32(TLSHandshake_header.Handshake__length);

	/* Read up to the session ID length byte. Since the session ID
   * is of variable length we need to figure out how much to read as such. */

	if (read_bytes(tls_in, &server_hello_intro,
		sizeof(server_hello_intro)) <= 0) {
		return -1;
	}
	must_read_bytes -= sizeof(server_hello_intro);

	server_version_major = server_hello_intro.server_version_major;
	server_version_minor = server_hello_intro.server_version_minor;

	stat_flags |= STAT_SERVER_VERSION;

#if __DEBUG__
	fprintf(stderr, "TLS ServerHello Version: %s (0x%02x%02x)\n",
		PROTOCOL_TXT(server_hello_intro.server_version_minor),
		server_hello_intro.server_version_major,
		server_hello_intro.server_version_minor);

	t = ntohl(server_hello_intro.random_gmt_unix_time);
	ts = localtime(&t);
	if (strftime(time_buf, sizeof(time_buf), "%b %d, %Y %H:%M:%S %Z", ts)) {
		fprintf(stderr, "TLS ServerHello Random gmt_unix_time: %s (%u)\n",
			time_buf, ntohl(server_hello_intro.random_gmt_unix_time));
	}

	fprintf(stderr, "TLS ServerHello Random random_bytes: ");
	for (i = 0; i < 28; i++)
		fprintf(stderr, "%02x", server_hello_intro.random_random_bytes[i]);
	fprintf(stderr, "\n");
#endif

	/* log */
	if (tls_out != -1) {
		r = write(tls_out, &server_hello_intro, sizeof(server_hello_intro));
		if (r == 0 || r == -1) {
			perror("write");
			return -1;
		}
	}

	if (read_bytes(tls_in, &server_hello_session.session_id_length,
		sizeof(server_hello_session.session_id_length)) <= 0) {
		return -1;
	}
	must_read_bytes -= sizeof(server_hello_session.session_id_length);

#if __DEBUG__
	fprintf(stderr, "TLS ServerHello Session ID Length: %u\n",
		server_hello_session.session_id_length);
#endif

	/* log */
	if (tls_out != -1) {
		r = write(tls_out, &server_hello_session.session_id_length,
			sizeof(server_hello_session.session_id_length));
		if (r == 0 || r == -1) {
			perror("write");
			return -1;
		}
	}

  /* Now we know we must read session_id_length bytes */

	assert(server_hello_session.session_id_length <=
		sizeof(server_hello_session.session_id));

	if (server_hello_session.session_id_length) {
		if (read_bytes(tls_in, server_hello_session.session_id,
			server_hello_session.session_id_length) <= 0) {
			return -1;
		}
		must_read_bytes -= server_hello_session.session_id_length;
	}

#if __DEBUG__
	for (i = 0; i < server_hello_session.session_id_length; i++) {
		if (i == 0) {
			fprintf(stderr, "TLS ServerHello Session ID: ");
		}
		fprintf(stderr, "%02x", server_hello_session.session_id[i]);
		if (i + 1 == server_hello_session.session_id_length) {
			fprintf(stderr, "\n");
		}
	}
#endif

	/* log */
	if (tls_out != -1) {
		if (server_hello_session.session_id_length) {
			r = write(tls_out, server_hello_session.session_id,
				server_hello_session.session_id_length);
			if (r == 0 || r == -1) {
				perror("write");
				return -1;
			}
		}
	}

	/* ciphersuite */

	if (read_bytes(tls_in, &server_hello_ciphersuite.cipher_suite,
		sizeof(server_hello_ciphersuite.cipher_suite)) <= 0) {
		return -1;
	}
	must_read_bytes -= sizeof(server_hello_ciphersuite.cipher_suite);

	server_suite = n16toh16(server_hello_ciphersuite.cipher_suite);

	stat_flags |= STAT_SERVER_SUITE;

#if __DEBUG__
	fprintf(stderr, "TLS ServerHello Cipher Suite: %s (0x%04x)\n",
		CIPHER_TXT(n16toh16(server_hello_ciphersuite.cipher_suite)),
		n16toh16(server_hello_ciphersuite.cipher_suite));
#endif

	/* log */
	if (tls_out != -1) {
		r = write(tls_out, &server_hello_ciphersuite.cipher_suite,
			sizeof(server_hello_ciphersuite.cipher_suite));
		if (r == 0 || r == -1) {
			perror("write");
			return -1;
		}
	}

	/* compression */

	if (read_bytes(tls_in, &server_hello_compression.compression_method,
		sizeof(server_hello_compression.compression_method)) <= 0) {
		return -1;
	}
	must_read_bytes -= sizeof(server_hello_compression.compression_method);

#if __DEBUG__
	fprintf(stderr, "TLS ServerHello Compression Method: %s (%u)\n",
		COMPRESSION_TXT(server_hello_compression.compression_method),
		server_hello_compression.compression_method);
#endif

	/* log */
	if (tls_out != -1) {
		r = write(tls_out, &server_hello_compression.compression_method,
			sizeof(server_hello_compression.compression_method));
		if (r == 0 || r == -1) {
			perror("write");
			return -1;
		}
	}

	/* extensions */

	if (must_read_bytes > 0) {
		if (read_bytes(tls_in, &extensions.extensions_length,
			sizeof(extensions.extensions_length)) <= 0) {
			return -1;
		}
		must_read_bytes -= sizeof(extensions.extensions_length);

#if __DEBUG__
		fprintf(stderr, "TLS ServerHello Extensions Length: %u\n",
			n16toh16(extensions.extensions_length));
#endif

		/* log */
		if (tls_out != -1) {
			r = write(tls_out, &extensions.extensions_length,
				sizeof(extensions.extensions_length));
			if (r == 0 || r == -1) {
				perror("write");
				return -1;
			}
		}

		/* Now we know we must read extensions_length bytes */

		assert(n16toh16(extensions.extensions_length) <=
			sizeof(extensions.extensions));

		if (n16toh16(extensions.extensions_length)) {
			if (read_bytes(tls_in, extensions.extensions,
				n16toh16(extensions.extensions_length)) <= 0) {
				return -1;
			}
			must_read_bytes -= n16toh16(extensions.extensions_length);
		}

		/* log */
		if (tls_out != -1) {
			if (n16toh16(extensions.extensions_length)) {
				r = write(tls_out, extensions.extensions,
					n16toh16(extensions.extensions_length));
				if (r == 0 || r == -1) {
					perror("write");
					return -1;
				}
			}
		}
	}

	/* Make sure we've read *exactly* Handshake__length bytes */

	assert(must_read_bytes == 0);

	return 0;
}


/*
 * process a TLS Handshake Certificate message
 *
 * Message consists of a { uint8_t certificate_list_length[3] } header
 * followed by one or more instances of { uint8_t certificate_length[3];
 * <certificate blob> }.
*/
int process_TLS_Handshake_Certificate()
{
	unsigned int r;

	unsigned int must_read_bytes;

	/* certificate list */

	if (read_bytes(tls_in, &certificate.certificate_list_length,
		sizeof(certificate.certificate_list_length)) <= 0) {
		return -1;
	}

	/* log */
	if (tls_out != -1) {
		r = write(tls_out, &certificate.certificate_list_length,
			sizeof(certificate.certificate_list_length));
		if (r == 0 || r == -1) {
			perror("write");
			return -1;
		}
	}

#if __DEBUG__
		fprintf(stderr, "TLS Certificates Length: %u\n",
			n24toh32(certificate.certificate_list_length));
#endif

	must_read_bytes = n24toh32(certificate.certificate_list_length);

	while(must_read_bytes > 0) {
		assert(must_read_bytes >= sizeof(asn1certificate_min));

		/* certificate */
		if (read_bytes(tls_in, &asn1certificate.certificate_length,
			sizeof(asn1certificate.certificate_length)) <= 0) {
			return -1;
		}
		must_read_bytes -= sizeof(asn1certificate.certificate_length);

		/* log */
		if (tls_out != -1) {
			r = write(tls_out, &asn1certificate.certificate_length,
				sizeof(asn1certificate.certificate_length));
			if (r == 0 || r == -1) {
				perror("write");
				return -1;
			}
		}

#if __DEBUG__
		fprintf(stderr, "TLS Certificate Length: %u\n",
			n24toh32(asn1certificate.certificate_length));
#endif

		assert(n24toh32(asn1certificate.certificate_length) <=
			sizeof(asn1certificate.certificate));

		if (read_bytes(tls_in, asn1certificate.certificate,
			n24toh32(asn1certificate.certificate_length)) <= 0) {
			return -1;
		}
		must_read_bytes -= n24toh32(asn1certificate.certificate_length);

		/* log */
		if (tls_out != -1) {
			r = write(tls_out, asn1certificate.certificate,
				n24toh32(asn1certificate.certificate_length));
			if (r == 0 || r == -1) {
				perror("write");
				return -1;
			}
		}

		/* invoke certificate handler if present */
		if (tls_callbacks[SSL3_RT_HANDSHAKE][SSL3_MT_CERTIFICATE]) {
			(*tls_callbacks[SSL3_RT_HANDSHAKE][SSL3_MT_CERTIFICATE])(
				asn1certificate.certificate,
				n24toh32(asn1certificate.certificate_length));
		}
	}

	return 0;
}


/*
 * Processes an SSL/TLS Handshake.
 */
int _tls()
{
	unsigned int r;

	unsigned int must_read_bytes;

	unsigned int bail_tls = 0;

	/* read socket buffer */
	char r_buf[BUF_SIZE+1];

	/* reset */
	error_tls = TLS_ERROR_NOOP;

	while(!bail_tls) {
		/* read SSL/TLS record header */
		if (read_bytes(tls_in, &TLSPlaintext_header,
			sizeof(TLSPlaintext_header)) <= 0) {
			return -1;
		}

		/* log */
		if (tls_out != -1) {
			r = write(tls_out, &TLSPlaintext_header, sizeof(TLSPlaintext_header));
			if (r == 0 || r == -1) {
				perror("write");
				return -1;
			}
		}

#if __DEBUG__
		fprintf(stderr,"\033[1;34m[.] TLS Record "
			"type:%u(%s) version:%u.%u length:%u\033[0m\n",
			TLSPlaintext_header.TLSPlaintext__type,
			TLSContentType(TLSPlaintext_header.TLSPlaintext__type),
			TLSPlaintext_header.TLSPlaintext__versionMajor,
			TLSPlaintext_header.TLSPlaintext__versionMinor,
			ntohs(TLSPlaintext_header.TLSPlaintext__length));
#endif

		TLSPlaintext__versionMajor = TLSPlaintext_header.TLSPlaintext__versionMajor;
		TLSPlaintext__versionMinor = TLSPlaintext_header.TLSPlaintext__versionMinor;

		stat_flags |= STAT_TLS_VERSION;

		/* process SSL/TLS record */
		switch(TLSPlaintext_header.TLSPlaintext__type) {
			/* alert (21) */
			case SSL3_RT_ALERT:
				/* there must be an alert header */
				assert(ntohs(TLSPlaintext_header.TLSPlaintext__length) >=
					sizeof(TLSAlert_header));

				if (read_bytes(tls_in, &TLSAlert_header,
					sizeof(TLSAlert_header)) <= 0) {
					return -1;
				}

				/* log */
				if (tls_out != -1) {
					r = write(tls_out, &TLSAlert_header, sizeof(TLSAlert_header));
					if (r == 0 || r == -1) {
						perror("write");
						return -1;
					}
				}

#if __DEBUG__
				fprintf(stderr,
					"\033[1;36m[.] TLS Alert "
					"level:%u(%s) description:%u(%s)\033[0m\n",
					TLSAlert_header.Alert__level,
					AlertLevel(TLSAlert_header.Alert__level),
					TLSAlert_header.Alert__description,
					AlertDescription(TLSAlert_header.Alert__description));
#endif

				error_tls = TLS_ERROR_ALERT;
				bail_tls = 1;
				break;
			/* handshake (22) */
			case SSL3_RT_HANDSHAKE:
				/* there must be a handshake header */
				assert(ntohs(TLSPlaintext_header.TLSPlaintext__length) >=
					sizeof(TLSHandshake_header));

				must_read_bytes =
					ntohs(TLSPlaintext_header.TLSPlaintext__length);

				while(must_read_bytes > 0) {
					/* read handshake header */
					if (read_bytes(tls_in, &TLSHandshake_header,
						sizeof(TLSHandshake_header)) <= 0) {
						return -1;
					}
					must_read_bytes -= sizeof(TLSHandshake_header);

					/* log */
					if (tls_out != -1) {
						r = write(tls_out, &TLSHandshake_header,
							sizeof(TLSHandshake_header));
						if (r == 0 || r == -1) {
							perror("write");
							return -1;
						}
					}

#if __DEBUG__
					fprintf(stderr,
						"\033[1;36m[.] TLS Handshake "
						"type:%u(%s) length:%u\033[0m\n",
						TLSHandshake_header.Handshake__type,
						TLSHandshakeType(TLSHandshake_header.Handshake__type),
						n24toh32(TLSHandshake_header.Handshake__length));
#endif

          /* The record layer fragments information blocks (e.g., handshake
					 * messages or application data) into TLSPlaintext records carrying
					 * data in chunks of 2^14 bytes or less.*/
          assert(ntohs(TLSPlaintext_header.TLSPlaintext__length) <= 0x4000);

#if 1
					/* We can't handle fragmentation right now.
					 * There's usually no reason to fragment messages that fit
					 * in a single record so the following assertion failing on
					 * larger messages should keep fragmentation away for now.
					 * Implementing fragmentation should include updating all
					 * handshake type handlers to account for their respective
					 * messages (e.g., server_hello) being fragmented and even
					 * for the fragments to appear interleaved.*/
					/* TODO: TLSHandshake_header.Handshake__length is NOT a reliable
					 * way to determine how much data is available right now. */
					assert(ntohs(TLSPlaintext_header.TLSPlaintext__length) >=
							sizeof(TLSHandshake_header) +
								n24toh32(TLSHandshake_header.Handshake__length));
#endif

					/* process Handshake type */
					switch(TLSHandshake_header.Handshake__type) {
						/* ClientHello (2) */
						case SSL3_MT_CLIENT_HELLO:
							if ((r = process_TLS_Handshake_ClientHello()) != 0) {return r;}
							break;
						/* ServerHello (2) */
						case SSL3_MT_SERVER_HELLO:
							if ((r = process_TLS_Handshake_ServerHello()) != 0) {return r;}
							break;
						/* Certificate (11) */
						case SSL3_MT_CERTIFICATE:
							/* save actual Certificate record */
							if ((r = process_TLS_Handshake_Certificate()) != 0) {return r;}
							break;
						/* Server Key Exchange (12) */
						case SSL3_MT_SERVER_KEY_EXCHANGE:
							/* consume (and ignore) rest of this record */
							assert(BUF_SIZE >=
								n24toh32(TLSHandshake_header.Handshake__length));

							if (read_bytes(tls_in, r_buf,
								n24toh32(TLSHandshake_header.Handshake__length)) <= 0) {
								return -1;
							}

							/* log */
							if (tls_out != -1) {
								r = write(tls_out, r_buf,
									n24toh32(TLSHandshake_header.Handshake__length));
								if (r == 0 || r == -1) {
									perror("write");
									return -1;
								}
							}
							break;
						/* Certificate Request (13) */
						case SSL3_MT_CERTIFICATE_REQUEST:
							/* consume (and ignore) rest of this record */
							assert(BUF_SIZE >=
								n24toh32(TLSHandshake_header.Handshake__length));

							if (read_bytes(tls_in, r_buf,
								n24toh32(TLSHandshake_header.Handshake__length)) <= 0) {
								return -1;
							}

							/* log */
							if (tls_out != -1) {
								r = write(tls_out, r_buf,
									n24toh32(TLSHandshake_header.Handshake__length));
								if (r == 0 || r == -1) {
									perror("write");
									return -1;
								}
							}
							break;
						/* ServerHelloDone (14)*/
						case SSL3_MT_SERVER_DONE:
							/* consume (and ignore) rest of this record */
							assert(BUF_SIZE >=
								n24toh32(TLSHandshake_header.Handshake__length));

							if (n24toh32(TLSHandshake_header.Handshake__length)) {
								if (read_bytes(tls_in, r_buf,
									n24toh32(TLSHandshake_header.Handshake__length)) <= 0) {
								return -1;
								}

								if (tls_out != -1) {
									r = write(tls_out, r_buf,
										n24toh32(TLSHandshake_header.Handshake__length));
									if (n24toh32(TLSHandshake_header.Handshake__length) &&
										(r == 0 || r == -1)) {
										perror("write");
										return -1;
									}
								}
							}

							error_tls = TLS_ERROR_NONE;
							bail_tls = 1;
							break;
						default:
#if __DEBUG__
							fprintf(stderr,
								"\033[1;31m[!] Unknown TLS handshake type:%u\033[0m\n",
								(unsigned int) TLSHandshake_header.Handshake__type);

							for (r = 0; r < sizeof(TLSHandshake_header); r++) {
								fprintf(stderr, "0x%02x ",
									*(((char *)&TLSHandshake_header) + r));
							}
							fprintf(stderr, "\n");
#endif

							error_tls = TLS_ERROR_UNKNOWN;
							bail_tls = 1;
							break;
					}

					must_read_bytes -=
						n24toh32(TLSHandshake_header.Handshake__length);
				}
				break;
			default:
#if __DEBUG__
				fprintf(stderr,
					"\033[1;31m[!] Unknown TLS record type:%u\033[0m\n",
					(unsigned int) TLSPlaintext_header.TLSPlaintext__type);

				for (r = 0; r < sizeof(TLSPlaintext_header); r++) {
					fprintf(stderr, "0x%02x ",
						*(((char *)&TLSPlaintext_header) + r));
				}
				fprintf(stderr, "\n");
#endif

				error_tls = TLS_ERROR_UNKNOWN;
				bail_tls = 1;
				break;
		}
	}

	return 0 || (error_tls != TLS_ERROR_NONE);
}


/* === API === */

int tls_live(void)
{
	int ret;
	unsigned int r;

	char buffer[
		sizeof(TLSPlaintext_header)  +
		sizeof(TLSHandshake_header)  +
		sizeof(client_hello_intro)   +
		sizeof(client_hello_session) +
		sizeof(client_hello_ciphersuites) +
		sizeof(client_hello_compression)];
	uint32_t i;

	if (!tls_initialized) {
#if __DEBUG__
		fprintf(stderr, "[!] Unitialized\n");
#endif
		return -1;
	}

	/* Open file descriptor to dump entire TLS conversation */
	char *s = strdup(CIPHER_TXT(opt_ciphersuites[0]));
	for (r = strlen(s) - 1; r >= 0 && isspace(s[r]); r--) {
		s[r] = '\0';
	}
	char tls_out_filename[0xFFFF]; /* should be enough :D */
	snprintf(tls_out_filename, sizeof(tls_out_filename),
		"%s.%u.%u.0x%04x_%s", "ssl", (uint8_t) PROTOCOLMAJOR,
		(uint8_t) PROTOCOLMINOR, (uint16_t) opt_ciphersuites[0], s);
	if (s) {
		free(s);
	}

	if (tls_out == -1) {
		if ((tls_out = open(tls_out_filename, O_CREAT | O_RDWR | O_TRUNC,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1) {
			perror("open");
			return -1;
		}
	}

	/* Build and Write ClientHello to initiate SSL handshake
	 *
	 * A ciphersuite must be specified by now (see tls_set_suite())
	 * otherwise the default (mandatory suite) will be used.
	 */

	/* prepare TLS Handshake ClientHello */
	prepare_TLS_Handshake_ClientHello();

	/* prepare TLS Handshake header */
	TLSHandshake_header.Handshake__type = SSL3_MT_CLIENT_HELLO;
	h24ton24(
		// ClientHello Version, Random fields; 34 bytes fixed
		sizeof(client_hello_intro) +
		// ClientHello Session ID; 1 bytes minimum
		sizeof(client_hello_session.session_id_length) +
			client_hello_session.session_id_length +
		// ClientHello Ciphersuites; 4 bytes minimum
		sizeof(client_hello_ciphersuites.cipher_suites_length) +
			n16toh16(client_hello_ciphersuites.cipher_suites_length) +
		// ClientHello Compression methods; 2 bytes minimum
		sizeof(client_hello_compression.compression_methods_length) +
			client_hello_compression.compression_methods_length,
		TLSHandshake_header.Handshake__length);

	/* prepare TLS record header */
	TLSPlaintext_header.TLSPlaintext__type = SSL3_RT_HANDSHAKE;
	TLSPlaintext_header.TLSPlaintext__versionMajor = PROTOCOLMAJOR;
	TLSPlaintext_header.TLSPlaintext__versionMinor = PROTOCOLMINOR;
	TLSPlaintext_header.TLSPlaintext__length = h16ton16(
		// TLS Handshake header; 4 bytes fixed
		sizeof(TLSHandshake_header) +
		// ClientHello message; 41 bytes minimum
		(uint16_t)n24toh32(TLSHandshake_header.Handshake__length));

	i = 0;
#if 0
	/* Write TLS record header */
	r = write(tls_in, &TLSPlaintext_header, sizeof(TLSPlaintext_header));
	if (r == 0 || r == -1) {
		perror("write");
		return -1;
	}

	/* log */
	if (tls_out != -1) {
		r = write(tls_out, &TLSPlaintext_header, sizeof(TLSPlaintext_header));
		if (r == 0 || r == -1) {
			perror("write");
			return -1;
		}
	}
#else
	assert(sizeof(buffer) >= i + sizeof(TLSPlaintext_header));
	memcpy(buffer + i, &TLSPlaintext_header, sizeof(TLSPlaintext_header));
	i += sizeof(TLSPlaintext_header);
#endif

#if 0
	/* Write TLS handshake header */
	r = write(tls_in, &TLSHandshake_header, sizeof(TLSHandshake_header));
	if (r == 0 || r == -1) {
		perror("write");
		return -1;
	}

	/* log */
	if (tls_out != -1) {
		r = write(tls_out, &TLSHandshake_header, sizeof(TLSHandshake_header));
		if (r == 0 || r == -1) {
			perror("write");
			return -1;
		}
	}
#else
	assert(sizeof(buffer) >= i + sizeof(TLSHandshake_header));
	memcpy(buffer + i, &TLSHandshake_header, sizeof(TLSHandshake_header));
	i += sizeof(TLSHandshake_header);
#endif

#if 0
	/* Write TLS ClientHello Version, Random fields */
	r = write(tls_in, &client_hello_intro, sizeof(client_hello_intro));
	if (r == 0 || r == -1) {
		perror("write");
		return -1;
	}

	/* log */
	if (tls_out != -1) {
		r = write(tls_out, &client_hello_intro, sizeof(client_hello_intro));
		if (r == 0 || r == -1) {
			perror("write");
			return -1;
		}
	}
#else
	assert(sizeof(buffer) >= i + sizeof(client_hello_intro));
	memcpy(buffer + i, &client_hello_intro, sizeof(client_hello_intro));
	i += sizeof(client_hello_intro);
#endif

#if 0
	/* Write TLS ClientHello Session ID */
	r = write(tls_in, &client_hello_session,
		sizeof(client_hello_session.session_id_length) +
			client_hello_session.session_id_length);
	if (r == 0 || r == -1) {
		perror("write");
		return -1;
	}

	/* log */
	if (tls_out != -1) {
		r = write(tls_out, &client_hello_session,
			sizeof(client_hello_session.session_id_length) +
				client_hello_session.session_id_length);
		if (r == 0 || r == -1) {
			perror("write");
			return -1;
		}
	}
#else
	assert(sizeof(buffer) >= i +
		sizeof(client_hello_session.session_id_length) +
			client_hello_session.session_id_length);
	memcpy(buffer + i, &client_hello_session,
		sizeof(client_hello_session.session_id_length) +
			client_hello_session.session_id_length);
	i += sizeof(client_hello_session.session_id_length) +
				client_hello_session.session_id_length;
#endif

#if 0
	/* Write TLS ClientHello Ciphersuites */
	r = write(tls_in, &client_hello_ciphersuites,
		sizeof(client_hello_ciphersuites.cipher_suites_length) +
			n16toh16(client_hello_ciphersuites.cipher_suites_length));
	if (r == 0 || r == -1) {
		perror("write");
		return -1;
	}

	/* log */
	if (tls_out != -1) {
		r = write(tls_out, &client_hello_ciphersuites,
			sizeof(client_hello_ciphersuites.cipher_suites_length) +
				n16toh16(client_hello_ciphersuites.cipher_suites_length));
		if (r == 0 || r == -1) {
			perror("write");
			return -1;
		}
	}
#else
	assert(sizeof(buffer) >= i +
		sizeof(client_hello_ciphersuites.cipher_suites_length) +
			n16toh16(client_hello_ciphersuites.cipher_suites_length));
	memcpy(buffer + i, &client_hello_ciphersuites,
		sizeof(client_hello_ciphersuites.cipher_suites_length) +
			n16toh16(client_hello_ciphersuites.cipher_suites_length));
	i += sizeof(client_hello_ciphersuites.cipher_suites_length) +
				n16toh16(client_hello_ciphersuites.cipher_suites_length);
#endif


#if 0
	/* Write TLS ClientHello Compression methods */
	r = write(tls_in, &client_hello_compression,
		sizeof(client_hello_compression.compression_methods_length) +
		client_hello_compression.compression_methods_length);
	if (r == 0 || r == -1) {
		perror("write");
		return -1;
	}

	/* log */
	if (tls_out != -1) {
		r = write(tls_out, &client_hello_compression,
			sizeof(client_hello_compression.compression_methods_length) +
				client_hello_compression.compression_methods_length);
		if (r == 0 || r == -1) {
			perror("write");
			return -1;
		}
	}
#else
	assert(sizeof(buffer) >= i +
		sizeof(client_hello_compression.compression_methods_length) +
			client_hello_compression.compression_methods_length);
	memcpy(buffer + i, &client_hello_compression,
		sizeof(client_hello_compression.compression_methods_length) +
			client_hello_compression.compression_methods_length);
	i += sizeof(client_hello_compression.compression_methods_length) +
			client_hello_compression.compression_methods_length;
#endif

	r = write(tls_in, buffer, i);
	if (r == 0 || r == -1) {
		perror("write");
		return -1;
	}

	/* log */
	if (tls_out != -1) {
		r = write(tls_out, buffer, i);
		if (r == 0 || r == -1) {
			perror("write");
			return -1;
		}
	}

	ret = _tls();

	if (tls_out != -1 && close(tls_out) == -1) {
		perror("close");
	}

	return ret;
}


int tls_replay()
{
	int ret;

	if (!tls_initialized) {
#if __DEBUG__
		fprintf(stderr, "[!] Unitialized\n");
		return -1;
#endif
	}

#if 1
	/* Open file descriptor to dump entire TLS conversation */
	if (tls_out == -1) {
		if ((tls_out = open("ssl.replay.dbg", O_CREAT | O_RDWR | O_TRUNC,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1) {
			perror("open");
			return -1;
		}
	}
#endif

	ret = _tls();

#if 1
	if (tls_out != -1 && close(tls_out) == -1) {
		perror("close");
	}
#endif

	return ret;
}


int tls_init (void)
{
	tls_in  = -1;
	tls_out = -1;

	/* clear callback pointers */
	memset(tls_callbacks, 0, sizeof(tls_callbacks));

	/* set default (RFC mandatory) ciphersuite. tls_set_suites() can change it. */
	opt_ciphersuites[0] = CIPHERSUITEMANDATORY;
	opt_ciphersuite_count = 1;

	/* clear statistics */
	stat_flags = 0;

	error_tls = TLS_ERROR_NOOP;

	tls_initialized = 1;

	return 0;
}

int tls_set_in (int fd)
{
	tls_in = fd;
	return 0;
}

int tls_set_out (int fd)
{
	tls_out = fd;
	return 0;
}

int tls_set_suites(uint16_t *suites, uint16_t suite_count)
{
	uint16_t i;

	/* Set ciphersuites to be used in ClientHello */
	for (i = 0; i < suite_count &&
		i < (sizeof(opt_ciphersuites)/sizeof(opt_ciphersuites[0])); i++) {
		opt_ciphersuites[i] = suites[i];
#if __DEBUG__
	fprintf(stderr, "TLS Initialized protocol_version:%u.%u (0x%04X) %s\n",
		PROTOCOLMAJOR, PROTOCOLMINOR, opt_ciphersuites[i],
		CIPHER_TXT(opt_ciphersuites[i]));
#endif
	}
	opt_ciphersuite_count = i;

	return 0;
}

int tls_set_cb_cert(int (*handler)(uint8_t *, uint32_t))
{
	tls_callbacks[SSL3_RT_HANDSHAKE][SSL3_MT_CERTIFICATE] = handler;
	return 0;
}

int tls_error()
{
	return error_tls;
}

void tls_print_suites()
{
  uint16_t i;

  for (i = 0; i < CIPHERSUITES; i++) {
    fprintf(stderr,
      "%3u CipherSuite %s = { 0x%02X,0x%02X };\n",
      CipherSuites[i], CIPHER_TXT(CipherSuites[i]),
      CipherSuites[i] >> 8, CipherSuites[i] & 0xFF);
  }
}

CipherSuite * tls_suites()
{
	return CipherSuites;
}

CipherSuite tls_suite_count()
{
	return CIPHERSUITES;
}

const char * tls_suite_name(uint16_t n)
{
	return CIPHER_TXT(n);
}

void tls_print_version()
{
  fprintf(stderr, "SSL/TLS protocol_version:%u.%u\n",
    PROTOCOLMAJOR, PROTOCOLMINOR);
  fprintf(stderr, "Available cipher_suites:%u\n", CIPHERSUITES);
}

uint8_t tls_stat_flags (void)
{
	return stat_flags;
}

uint8_t tls_suite_version_major (void)
{
	return PROTOCOLMAJOR;
}

uint8_t tls_suite_version_minor (void)
{
	return PROTOCOLMINOR;
}

uint8_t tls_version_major (void)
{
	return TLSPlaintext__versionMajor;
}

uint8_t tls_version_minor (void)
{
	return TLSPlaintext__versionMinor;
}

uint8_t tls_server_version_major (void)
{
	return server_version_major;
}

uint8_t tls_server_version_minor (void)
{
	return server_version_minor;
}

uint16_t tls_server_suite (void)
{
	return server_suite;
}
