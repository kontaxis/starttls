/* kontaxis 2014-10-06 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <errno.h>

#include "tls_api.h"

#define CRT_FNAME_TMPL "x509-NN.der"
#define CRT_FNAME_MXSZ sizeof(CRT_FNAME_TMPL)

int certificate_handler (uint8_t *certificate, uint32_t certificate_length)
{
	static uint32_t crt_count = 0;
	char crt_fname[CRT_FNAME_MXSZ];
	int fd;

	uint32_t i;

	fprintf(stderr, ">> Certificate %u bytes\n>> ", certificate_length);
	for (i = 0; i < 30; i++) {
		fprintf(stderr, "0x%02x ", certificate[i]);
		if ((i + 1) % 10 == 0) fprintf(stderr, "\n>> ");
	}
	fprintf(stderr, "[...]\n");

	/* Output the certificate in its original format (DER).
	 * Since certificate_handler() with certificates in the order they appear
	 * in the trace (order received from the server) x509-0.der is the host's
	 * certificate followed by one or more (i.e., x509-1.der and x509-2.der)
	 * CA certificates.
	 *
	 * Hint: openssl x509 -inform DER -text -noout -in x509-0.der
	 */
	if (crt_count > 99) {
		crt_count = 0;
	}
	snprintf(crt_fname, CRT_FNAME_MXSZ, "x509-%d.der", crt_count);
	if ((fd = open(crt_fname, O_RDWR | O_TRUNC | O_CREAT,
		S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1) {
		perror("open");
	} else {
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

int main (int argc, char *argv[])
{
	int r;
	int tls_trace_fd;

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

	tls_init();

	tls_set_in(tls_trace_fd);

	/* register callback to receive individual ASN1 certificates
	 * from Certificate handshake message */
	tls_set_cb_cert(&certificate_handler);

	r = tls_replay();

	if (close(tls_trace_fd) == -1) {
		perror("close");
	}

	return r;
}
