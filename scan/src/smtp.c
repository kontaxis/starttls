/* 
 * SMTP STARTTLS test program used to probe and capture ServerHello responses
 * and Certificates.
 *
 * - https://tools.ietf.org/html/rfc2821
 * - https://tools.ietf.org/html/rfc1893
 * - https://tools.ietf.org/html/rfc3207
 *
 * kontaxis 2014-10-06
 */

#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>

#include "tls_api.h"

/* SMTP default port */
#define DEFAULT_TARGET_PORT_TCP ((uint16_t) 25)

/* generic socket read/write buffers are this big */
#define BUF_SIZE 0xFFFF


unsigned int error_smtp;

/*
 * Carries out an SMTP greeting and requests STARTTLS.
 */
int ehlo(int sockfd)
{
	unsigned int i, r;

	/* read/write socket buffers */
	char r_buf[BUF_SIZE+1];
	char w_buf[BUF_SIZE+1];

	error_smtp = 0;
	unsigned int bail_smtp  = 0;

	unsigned int starttls_requested = 0;

	/* points to the beginning of each line in an SMTP server response */
	char *line;
	/* contains the SMTP response code found in the beginning of a line */
	long int smtp_code;

	/* SMTP talk. Get to STARTTLS or exit */
	while(!bail_smtp) {
		/* read server's SMTP response */
		i = 0; r = 0;
		memset(r_buf, 0, BUF_SIZE+1);
		while(1) {
			r = read(sockfd, r_buf + i, BUF_SIZE - i);
			if (r == 0 || r == -1) {
				if (r == 0) {
#if __DEBUG__
					fprintf(stderr, "EOF or peer has performed socket shutdown.\n");
#endif
				} else {
					perror("read");
				}
				return -1;
			}

			i += r;
			/* make sure we have complete lines in the response */
			if (r_buf[i-2] == '\r' && r_buf[i-1] == '\n') {
				break;
			}
		}
		r = i;

		/* print server's response */
		fprintf(stdout, "%s", r_buf);

		/* process server's response */
		line = r_buf;
		smtp_code = 0;
		for (i = 0; i < r; i++) {
			/* end of line */
			if (r_buf[i] == '\r' && i + 1 < r && r_buf[i+1] == '\n') {
				r_buf[i] = '\0';
				/* get SMTP code from the beginning of the line */
				smtp_code = strtol(line, NULL, 10);
				assert(smtp_code != LONG_MIN && smtp_code != LONG_MAX);
#if __DEBUG__
				fprintf(stderr, "\033[1;35m[-] (%ld) %s\033[0m\n", smtp_code, line);
#endif
				/* last line, nuke the rest of the response and stop parsing */
				if (r_buf + i - line > 3 && line[3] == ' ') {
					memset(r_buf + i, 0, BUF_SIZE - i);
					break;
				}
				i += 2;
				line = r_buf + i;
				/* invalidate SMTP code; this is not the last line of this response */
				smtp_code = 0;
			}
		}

		/* interpret server's response */
		switch(smtp_code) {
			/* Greeting = "220 " Domain [ SP text ] CRLF */
			/* 220 <domain> Service ready */
			case 220:
				if (!starttls_requested) {
					/* respond to server's greeting: EHLO client.example.org */
					memset(w_buf, 0, BUF_SIZE+1);
					snprintf(w_buf + 0, 5+1, "%s", "EHLO ");
#ifdef __HOSTNAME__
					snprintf(w_buf + 5, BUF_SIZE-5-2, "%s", __HOSTNAME__);
#else
					snprintf(w_buf + 5, BUF_SIZE-5-2, "%s", "www.example.com");
#endif
					snprintf(w_buf + strlen(w_buf), 2+1, "\r\n");

					r = write(sockfd, w_buf, strlen(w_buf));
					if (r == 0 || r == -1) {
						perror("write");
						return -1;
					}

					/* print our response */
					fprintf(stdout, "%s", w_buf);
				}
				else {
					bail_smtp = 1;
					tls_set_in(sockfd);
					return tls_live();
				}
				break;
			/* Reply-line = Reply-code [ SP text ] CRLF */
			/* 250 Requested mail action okay, completed */
			case 250:
				/* in our case it's to the EHLO greeting */

				/* respond to server's response: STARTTLS */
				memset(w_buf, 0, BUF_SIZE+1);
				snprintf(w_buf, strlen("STARTTLS") + 2 + 1, "STARTTLS\r\n");

				/* set STARTTLS requested flag */
				starttls_requested = 1;

				r = write(sockfd, w_buf, strlen(w_buf));
				if (r == 0 || r == -1) {
					perror("write");
					return -1;
				}

				/* print our response */
				fprintf(stdout, "%s", w_buf);
				break;
			default:
#if __DEBUG__
				fprintf(stderr, "\033[1;31m[!] Unknown SMTP code: %ld\033[0m\n",
					smtp_code);

				for (i = 0; i < r; i++) {
					fprintf(stderr, "\\x%02x", r_buf[i]);
				}
				fprintf(stderr,"\n");
#endif
				bail_smtp = 1;
				error_smtp = 1;
				break;
		}
	}

	return 0 || error_smtp;
}


/*
 * Connects to target ands the connection off to the SMTP logic
 * (which may hand it off to the TLS logic).
 */
int probe(char *target, uint16_t port, uint8_t tls_direct)
{
	int sockfd;
	struct sockaddr_in servaddr;
	/* timeout */
	struct timeval t;
	int r;

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		return -1;
	}

	/* 10 second timeout to send or receive any data */
	t.tv_sec  = 10;
	t.tv_usec = 0;
	if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (void *)&t,
				sizeof(struct timeval)) == -1 ||
			setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (void *)&t,
				sizeof(struct timeval)) == -1) {
		perror("setsockopt");
		return -1;
	}

	bzero(&servaddr,sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	if (inet_aton(target, &servaddr.sin_addr) == 0) {
		fprintf(stderr, "FATAL: invalid IP address\n");
		return -1;
	}
	servaddr.sin_port=htons(port);

	if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1) {
		perror("connect");
		return -1;
	}

#if __DEBUG__
	fprintf(stderr, "\033[1;32m[*] Connected\033[0m\n");
#endif

	if (!tls_direct) {
		/* Speak SMTP leading up to STARTTLS */
		r = ehlo(sockfd);
	} else {
		tls_set_in(sockfd);
		r = tls_live();
	}

#if __DEBUG__
	fprintf(stderr,
		"\033[1;32m[*] Error:%d, SMTP:%d, TLS:%d(%s)\033[0m\n",
		r, error_smtp, tls_error(), (tls_error() == TLS_ERROR_NONE)?"OK":"ERR");
#endif

	if (close(sockfd) == -1) {
		perror("close");
		return -1;
	}

	return r;
}


void present_result (uint16_t *suites, uint16_t suite_count)
{
	int i;
	uint16_t y;

	fprintf(stderr, "%s", tls_error() == TLS_ERROR_NONE?
		"\033[1;32m[SUPPORTED  ] ":"\033[1;31m[UNSUPPORTED] ");

	/* Print the SSL/TLS protocol the client used. */
	fprintf(stderr, "SSL%u.%u:",
		tls_suite_version_major(), tls_suite_version_minor());

	/* Print the protocol reported in the last SSL/TLS record.
	 * (what the server used) */
	if (TLS_VERSION_VALID) {
		fprintf(stderr, "SSL%u.%u/",
			tls_version_major(), tls_version_minor());
	} else {
		fprintf(stderr, "SSLNAN/");
	}

	/* Print the protocol reported in the last SSL/TLS Handshake record.
	 * (what the server used) For unsupported ciphersuites we don't get this. */
	if (TLS_SERVER_VERSION_VALID) {
		fprintf(stderr, "SSL%u.%u ",
			tls_server_version_major(), tls_server_version_minor());
	} else {
		fprintf(stderr, "SSLNAN ");
	}

	/* Print ciphersuites offered to the server (ClientHello) */
	for (y = 0; y < suite_count; y++) {
		fprintf(stderr, "0x%04X", suites[y]);
		if (y + 1 < suite_count) {
			fprintf(stderr, ",");
		} else fprintf(stderr, ":");
	}

	/* Print the ciphersuite accepted by the server (ServerHello) */
	if (TLS_SERVER_SUITE_VALID) {
		fprintf(stderr, "0x%04X ", tls_server_suite());
	} else {
		fprintf(stderr, "NANANA ");
	}

	/* Print names of the ciphersuites offered to the server (ClientHello) */
	for (y = 0; y < suite_count; y++) {
		char *s = strdup(tls_suite_name(suites[y]));
		for (i = strlen(s) - 1; i >= 0 && isspace(s[i]); i--) {
			s[i] = '\0';
		}
		fprintf(stderr, "%s", s);
		if (s) {
			free(s);
		}
		if (y + 1 < suite_count) {
			fprintf(stderr, ",");
		} else fprintf(stderr, ":");
	}

	/* Print the name of ciphersuite accepted by the server (ServerHello) */
	if (TLS_SERVER_SUITE_VALID) {
		char *s = strdup(tls_suite_name(tls_server_suite()));
		for (i = strlen(s) - 1; i >= 0 && isspace(s[i]); i--) {
			s[i] = '\0';
		}
		fprintf(stderr, "%s\033[0m\n", s);
		if (s) {
			free(s);
		}
	} else {
		fprintf(stderr,"UNAVAILABLE\033[0m\n");
	}
}


int open_dump_file (char * opt_dump_dir, uint16_t suite)
{
	int r;

	if (!opt_dump_dir) {
		return -1;
	}

	/* Open file descriptor to dump entire TLS conversation */
  char *s = strdup(tls_suite_name(suite));
  for (r = strlen(s) - 1; r >= 0 && isspace(s[r]); r--) {
    s[r] = '\0';
  }
  char tls_out_filename[0xFFFF]; /* should be enough :D */
  snprintf(tls_out_filename, sizeof(tls_out_filename),
    "%s/%s.%u.%u.0x%04x_%s", opt_dump_dir, "ssl",
		(uint8_t) tls_suite_version_major(),
    (uint8_t) tls_suite_version_minor(), (uint16_t) suite, s);
  if (s) {
    free(s);
  }

	if ((r = open(tls_out_filename, O_CREAT | O_RDWR | O_TRUNC,
      S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1) {
      perror("open");
  }

	return r;
}


/* Flags indicating that a particular command-line option has been set. */
#define OPT_TARGET_ADDR_IP4 (0x1 << 0)
#define OPT_TARGET_PORT_TCP (0x1 << 1)
#define OPT_CIPHERSUITE     (0x1 << 2)
/* Set when the specified ciphersuite has been found
 * in the current SSL/TLS spec. OPT_CIPHERSUITE must
 * be on for this to have any meaning. */
#define OPT_CIPHERSUITE_OK  (0x1 << 3)
/* Skip the SMTP talk leading up to STARTTLS and start with SSL/TLS directly.
 * First packet over the socket will be a ClientHello. */
#define OPT_TLS_DIRECT      (0x1 << 4)
#define OPT_DUMP_DIR        (0x1 << 5)

#define ERROR_RESERVED 0
#define ERROR_FATALUFO 1 /* fatal unknown */
#define ERROR_ARGS     2
#define ERROR_NOOP     3
#define ERROR_NONE     4 /* success */
/* Connection failure: bad address, connection refused, etc. */
#define ERROR_IO          10
#define ERROR_IO_CONNECT  11
#define ERROR_IO_SHUTDOWN 12
#define ERROR_IO_RESET    13
#define ERROR_IO_TIMEOUT  14
/* SMTP talk failure: no STARTTLS (probably other reasons too) */
#define ERROR_SMTP    20
/* Handshake failure: unsupported ciphersuite (probably other reasons too) */
#define ERROR_TLS     30

int main(int argc, char**argv)
{
	int error;

	int i;
	long j;
	char *o,*t;
	uint16_t x, y;

	/* Flags indicating that a particular command-line option has been set. */
	uint8_t opt_flags;
	/* RFC number of the ciphersuites to be used.
	 * (opt_flags & OPT_CIPHERSUITE) */
	uint16_t opt_ciphersuites[0xFFFF + 1];
	uint16_t opt_ciphersuite_count;
	/* String containing the address of the target server.
	 * (opt_flags & OPT_TARGET_ADDR_IP4) */
	char *   opt_target_addr;
	/* Port number the target server is listening to.
	 * (opt_flags & OPT_TARGET_PORT_TCP) */
	uint16_t opt_target_port;
	char * opt_dump_dir;
	int    opt_dump_fd;

	/* array of ciphersuite RFC numbers available in the current SSL/TLS spec */
	uint16_t * CipherSuites;
	uint16_t   CipherSuite_count;

	error = ERROR_NOOP;
	opt_flags = 0x00000000;
	opt_ciphersuite_count = 0;

	while ((i = getopt(argc, argv, "hvlo:s:x:dp:t:")) != -1) {
		switch(i) {
			case 'h':
				fprintf(stderr,
					"Use: %s [-h] [-v] [-l] [-s ciphersuite] [-x ciphersuite] "
					"[-p port] -t <IP address> \n", argv[0]);
				fprintf(stderr, "-h: prints use instructions (this)\n");
				fprintf(stderr, "-v: version information\n");
				fprintf(stderr, "-l: prints available ciphersuites\n");
				fprintf(stderr, "-o: sets dump output directory\n");
				fprintf(stderr,
					"-s: uses only specified ciphersuite (vs all), base10 integer\n");
				fprintf(stderr, "-x: same as -s but in base16\n");
				fprintf(stderr, "-d: proceeds with SSL/TLS directly (no SMTP talk)\n");
				fprintf(stderr, "-p: destination TCP Port (defaults to %u)\n",
					DEFAULT_TARGET_PORT_TCP);
				fprintf(stderr, "-t: target IPv4 address (mandatory)\n");
				return ERROR_ARGS;
				break;
			case 'v':
				tls_print_version();
				return ERROR_ARGS;
				break;
			case 'l':
				tls_print_suites();
				return ERROR_ARGS;
				break;
			case 'o':
				opt_flags |= OPT_DUMP_DIR;
				opt_dump_dir = optarg;
				break;
			case 's':
				o = strdup(optarg);
				t = strtok(o, ",");
				while (t) {
					i = atoi(t);
					if (i >= 0 && i <= ((uint16_t) ~0x0)) {
						opt_flags |= OPT_CIPHERSUITE;
						opt_ciphersuites[opt_ciphersuite_count++] = (uint16_t) i;
#if __DEBUG__
						fprintf(stderr,
							"\033[1;32m[*] Cipher Suite: (%u) %s\033[0m\n",
							opt_ciphersuites[opt_ciphersuite_count-1],
							tls_suite_name(opt_ciphersuites[opt_ciphersuite_count-1]));
#endif
					}
					else {
#if __DEBUG__
						fprintf(stderr,
							"[*] Invalid Cipher Suite %d. Ignoring. Try with -l\n", i);
#endif
					}
					t = strtok(NULL, ",");
				}
				free(o);
				break;
			case 'x':
				o = strdup(optarg);
				t = strtok(o, ",");
				while (t) {
					j = strtol(t, NULL, 16);
					if (j >= 0 && j <= ((uint16_t) ~0x0)) {
						opt_flags |= OPT_CIPHERSUITE;
						opt_ciphersuites[opt_ciphersuite_count++] = (uint16_t) j;
#if __DEBUG__
						fprintf(stderr, "\033[1;32m[*] Cipher Suite: (0x%04x) %s\033[0m\n",
							opt_ciphersuites[opt_ciphersuite_count-1],
							tls_suite_name(opt_ciphersuites[opt_ciphersuite_count-1]));
#endif
					}
					else {
#if __DEBUG__
						fprintf(stderr,
							"[*] Invalid Cipher Suite %ld. Ignoring. Try with -l\n", j);
#endif
					}
					t = strtok(NULL, ",");
				}
				free(o);
				break;
			case 'd':
				opt_flags |= OPT_TLS_DIRECT;
				break;
			case 'p':
				i = atoi(optarg);
				if (i >= 0 && i <= ((uint16_t) ~0x0)) {
					opt_flags |= OPT_TARGET_PORT_TCP;
					opt_target_port = (uint16_t) i;
#if __DEBUG__
					fprintf(stderr, "\033[1;32m[*] Target TCP Port: %u\033[0m\n",
						opt_target_port);
#endif
				}
				else {
#if __DEBUG__
					fprintf(stderr,
						"[*] Invalid Destination Port %d. Ignoring.\n", i);
#endif
				}
				break;
			case 't':
				opt_flags |= OPT_TARGET_ADDR_IP4;
				opt_target_addr = optarg;
#if __DEBUG__
				fprintf(stderr, "\033[1;32m[*] Target IPv4 address: %s\033[0m\n",
					opt_target_addr);
#endif
				break;
			default:
				break;
		}
	}

	if ((opt_flags & OPT_TARGET_PORT_TCP) == 0) {
		opt_target_port = DEFAULT_TARGET_PORT_TCP;
	}

	if ((opt_flags & OPT_TARGET_ADDR_IP4) == 0) {
		fprintf(stderr, "[!] Fatal. Missing target IP address. Try with -h\n");
		return ERROR_ARGS;
	}

	CipherSuites = tls_suites();
	CipherSuite_count = tls_suite_count();

	/* Validate specified ciphersuites */
	if (opt_flags & OPT_CIPHERSUITE) {
		for (y = 0; y < opt_ciphersuite_count; y++) {
			opt_flags &= ~OPT_CIPHERSUITE_OK; // clear
			for (x = 0; x < CipherSuite_count; x++) {
				if (CipherSuites[x] == opt_ciphersuites[y]) {
					opt_flags |= OPT_CIPHERSUITE_OK;
					break;
				}
			}
			if (!(opt_flags & OPT_CIPHERSUITE_OK)) {
				fprintf(stderr,
					"[!] Fatal. Invalid/unavailable cipher Suite: (0x%04x) %s\n",
					opt_ciphersuites[y], tls_suite_name(opt_ciphersuites[y]));
				return ERROR_NOOP;
			}
		}
	}

#if __DEBUG__
	tls_print_version();
#endif

	/* If specific ciphersuites have been specified, do only use those. 
	 * Else, go over all ciphersuites assuming the target supports STARTTLS.
   * Abort on SMTP error. */
	for (x = 0; x < CipherSuite_count; x++) {
		/* Set ciphersuite(s) to be used */
		tls_init();
		if (opt_flags & OPT_CIPHERSUITE) {
			tls_set_suites(opt_ciphersuites, opt_ciphersuite_count);
		}
		else {
			tls_set_suites(CipherSuites + x, 1);
			opt_ciphersuites[0] = CipherSuites[x];
			opt_ciphersuite_count = 1;
		}

		if ((opt_flags & OPT_DUMP_DIR) && (opt_dump_fd =
				open_dump_file(opt_dump_dir, opt_ciphersuites[0])) != -1) {
			tls_set_out(opt_dump_fd);
		}

		/* probe */
		error = probe(opt_target_addr, opt_target_port,
			opt_flags & OPT_TLS_DIRECT);

		/* bail immediately or continue? */
		switch(error) {
			/* I/O error (fatal) */
			case -1:
				switch(errno) {
					/* Timeout during connect (SYN) */
					case EINPROGRESS:
						return ERROR_IO_CONNECT;
						break;
					/* Connect failed (SYN, RST) */
					case ECONNREFUSED:
						return ERROR_IO_CONNECT;
						break;
					/* Other end abruptly shut down an existing connection (RST) */
					case ECONNRESET:
						return ERROR_IO_RESET;
						break;
					/* Other end gracefully shut down an existing connection (FIN) */
					case 0:
						return ERROR_IO_SHUTDOWN;
						break;
					/* Timeout during read */
					case EAGAIN:
						return ERROR_IO_TIMEOUT;
						break;
					default:
#if __DEBUG__ || 1
						fprintf(stderr, "%u:? %d\n", __LINE__, errno);
#endif
						return ERROR_IO;
						break;
				}
				break;

			/* TLS supported */
			case  0:
				assert(tls_error() == TLS_ERROR_NONE);
				error = ERROR_NONE;
				break;
			/* SMTP (fatal) or TLS error (conditional fatality) */
			case  1:
				if (error_smtp) {
					fprintf(stderr,
						"\033[1;31m[!] SMTP_ERROR. No STARTTLS?\033[0m\n");
					return ERROR_SMTP;
				}

				switch(tls_error()) {
					case TLS_ERROR_ALERT:
						/* TLS unsupported */
						error = ERROR_TLS;
						break;
					default:
#if __DEBUG__
						fprintf(stderr, "%u:? %d\n", __LINE__, errno);
#endif
						return ERROR_FATALUFO;
						break;
				}
				break;

			/* Unhandled error case */
			default:
#if __DEBUG__
						fprintf(stderr, "%u:? %d\n", __LINE__, errno);
#endif
				return ERROR_FATALUFO;
				break;
		}

		present_result(opt_ciphersuites, opt_ciphersuite_count);

		if (opt_flags & OPT_CIPHERSUITE) {
			break;
		}

		/* mandatory sleep to not overwhelm the server */
		if (x + 1 < CipherSuite_count) {sleep(10);}
	}

	return error;
}
