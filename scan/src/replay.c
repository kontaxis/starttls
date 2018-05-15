/* kontaxis 2014-10-06 */

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "tls_api.h"

#define CRT_FNAME_TMPL "x509-NN.der"
#define CRT_FNAME_MXSZ sizeof(CRT_FNAME_TMPL)

int tls_handshake_certificate_handler (
	uint8_t *certificate, uint32_t certificate_length)
{
	static uint32_t crt_count = 0;
	char crt_fname[CRT_FNAME_MXSZ];
	int fd;

	uint32_t i;

	fprintf(stderr, ">> Certificate %u bytes\n", certificate_length);
	if (certificate_length > 0) {
		fprintf(stderr, ">> ");
	}
	for (i = 0; i < 30 && i < certificate_length; i++) {
		fprintf(stderr, "0x%02x ", certificate[i]);
		if ((i + 1) % 10 == 0) {
			fprintf(stderr, "\n>> ");
		}
	}
	if (certificate_length > 0) {
		fprintf(stderr, "[...]\n");
	}

	/* Output the certificate in its original format (DER).
	 * Since certificate_handler() with certificates in the order they appear
	 * in the trace (order received from the server) x509-0.der is the host's
	 * certificate followed by one or more (i.e., x509-1.der and x509-2.der)
	 * CA certificates.
	 *
	 * Hint: openssl x509 -inform DER -text -noout -in x509-0.der
	 */
	if (crt_count > 99) {
		fprintf(stderr,
			">> [!] Certificate output to files has been truncated.\n");
		fd = -1;
	} else {
		snprintf(crt_fname, CRT_FNAME_MXSZ, "x509-%02d.der", crt_count);
		if ((fd = open(crt_fname, O_RDWR | O_TRUNC | O_CREAT,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1) {
			perror("open");
		}
	}
	if (fd != -1) {
		if (write(fd, certificate, certificate_length) != certificate_length) {
			perror("write");
		}

		if (close(fd) != 0) {
			perror("close");
		}
	}
	crt_count += 1;

	return 0;
}

#define n16toh16(n) \
((uint16_t) (((uint16_t) n) << 8) | (uint16_t) (((uint16_t) n) >> 8))

#define SERVER_KX_DH_FNAME_TMPL "server_kx_dh-NN"
#define SERVER_KX_DH_FNAME_MXSZ sizeof(SERVER_KX_DH_FNAME_TMPL)

int tls_handshake_server_key_exchange_dh_handler (
	struct ServerDHParams *params)
{
	static uint32_t kx_dh_count = 0;
	char kx_dh_fname[SERVER_KX_DH_FNAME_MXSZ];
	FILE *fp;

	uint32_t i;

	/* Prime modulus for the Diffie-Hellman operation. */

	fprintf(stderr, ">> Diffie-Hellman Prime Modulus Length: %u\n",
		n16toh16(params->dh_p_length));

	if (n16toh16(params->dh_p_length) > 0) {
		fprintf(stderr, ">> ");
	}
	for (i = 0; i < 30 && i < n16toh16(params->dh_p_length); i++) {
		fprintf(stderr, "0x%02x ", params->dh_p[i]);
		if ((i + 1) % 10 == 0) {
			fprintf(stderr, "\n>> ");
		}
	}
	if (n16toh16(params->dh_p_length) > 0) {
		fprintf(stderr, "[...]\n");
	}

	/* Generator used for the Diffie-Hellman operation. */

	fprintf(stderr, ">> Diffie-Hellman Generator Length: %u\n",
		n16toh16(params->dh_g_length));

	if (n16toh16(params->dh_g_length) > 0) {
		fprintf(stderr, ">> ");
	}
	for (i = 0; i < 30 && i < n16toh16(params->dh_g_length); i++) {
		fprintf(stderr, "0x%02x ", params->dh_g[i]);
		if ((i + 1) % 10 == 0) {
			fprintf(stderr, "\n>> ");
		}
	}
	if (n16toh16(params->dh_g_length) > 0) {
		fprintf(stderr, "[...]\n");
	}

	/* The server's Diffie-Hellman public value (g^X mod p). */

	fprintf(stderr, ">> Diffie-Hellman Public Value Length: %u\n",
		n16toh16(params->dh_Ys_length));

	if (n16toh16(params->dh_Ys_length) > 0) {
		fprintf(stderr, ">> ");
	}
	for (i = 0; i < 30 && i < n16toh16(params->dh_Ys_length); i++) {
		fprintf(stderr, "0x%02x ", params->dh_Ys[i]);
		if ((i + 1) % 10 == 0) {
			fprintf(stderr, "\n>> ");
		}
	}
	if (n16toh16(params->dh_Ys_length) > 0) {
		fprintf(stderr, "[...]\n");
	}

	/* Write to disk. */

	if (kx_dh_count > 99) {
		fprintf(stderr,
			">> [!] ServerKeyExchange output to files has been truncated.\n");
		fp = NULL;
	} else {
		snprintf(kx_dh_fname, SERVER_KX_DH_FNAME_MXSZ, "server_kx_dh-%02d",
			kx_dh_count);
		if ((fp = fopen(kx_dh_fname, "w")) == NULL) {
			perror("fopen");
		}
	}
	if (fp) {
		fprintf(fp, "Diffie-Hellman Server Params\n");

		fprintf(fp, "p Length: %u\n", n16toh16(params->dh_p_length));

		if (n16toh16(params->dh_p_length) > 0) {
			fprintf(fp, "p: ");
		}
		for (i = 0; i < n16toh16(params->dh_p_length); i++) {
			fprintf(fp, "%02x", params->dh_p[i]);
		}
		if (n16toh16(params->dh_p_length) > 0) {
			fprintf(fp, "\n");
		}

		fprintf(fp, "g Length: %u\n", n16toh16(params->dh_g_length));

		if (n16toh16(params->dh_g_length) > 0) {
			fprintf(fp, "g: ");
		}
		for (i = 0; i < n16toh16(params->dh_g_length); i++) {
			fprintf(fp, "%02x", params->dh_g[i]);
		}
		if (n16toh16(params->dh_g_length) > 0) {
			fprintf(fp, "\n");
		}

		fprintf(fp, "Pubkey Length: %u\n", n16toh16(params->dh_Ys_length));

		if (n16toh16(params->dh_Ys_length) > 0) {
			fprintf(fp, "Pubkey: ");
		}
		for (i = 0; i < n16toh16(params->dh_Ys_length); i++) {
			fprintf(fp, "%02x", params->dh_Ys[i]);
		}
		if (n16toh16(params->dh_Ys_length) > 0) {
			fprintf(fp, "\n");
		}

		if (fclose(fp) != 0) {
			perror("fclose");
		}
	}
	kx_dh_count += 1;

	return 0;
}

int tls_handshake_server_key_exchange_handler (uint8_t *ServerKeyExchange,
	uint32_t ServerKeyExchangeType)
{
	/*
	 * {
	 *   ServerDHParams params;
	 *   [...]
	 * } ServerKeyExchange;
	 */
	if (ServerKeyExchangeType & SERVER_KEYEXCHANGE_DHPARAMS) {
		struct ServerKeyExchange_DHparams *kx =
			(struct ServerKeyExchange_DHparams *)ServerKeyExchange;
		tls_handshake_server_key_exchange_dh_handler(kx->params);
		return 0;
	}

	return 0;
}

int main (int argc, char *argv[])
{
	int r;
	int tls_trace_fd;
	int tls_dbg_o_fd;

	char *tls_trace_path;

	if (argc < 2) {
		tls_print_version();
		tls_print_suites();
		fprintf(stderr, "Usage: %s tls_trace\n", argv[0]);
		return -1;
	}

	if ((tls_trace_fd = open(argv[1], O_RDONLY)) == -1) {
		perror("open");
		return -1;
	}

	if ((tls_dbg_o_fd = open("ssl.replay.dbg", O_CREAT | O_RDWR | O_TRUNC,
		S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1) {
		perror("open");
		return -1;
	}

	/* Set the current working directory to where the trace file is.
	 * This results in new files being created (e.g., x509-*.der) in
	 * the same directory as the trace itself.
	 * Failure to change directory is not a deal breaker. */
	tls_trace_path = dirname(argv[1]);
	if (chdir(tls_trace_path) == -1) {
		perror("chdir");
	}

	tls_init();

	tls_set_in(tls_trace_fd);

	tls_set_out(tls_dbg_o_fd);

	/* register callback to receive individual ASN1 certificates
	 * from Certificate handshake message */
	tls_set_callback_handshake_certificate(&tls_handshake_certificate_handler);

	/* register callback to receive ServerKeyExchange messages */
	tls_set_callback_handshake_server_key_exchange(
		&tls_handshake_server_key_exchange_handler);

	r = tls_replay();

	if (close(tls_trace_fd) == -1) {
		perror("close");
	}

	return r;
}
