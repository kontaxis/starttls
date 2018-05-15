#ifndef __AUX_H__
#define __AUX_H__

/* kontaxis 2014-10-06 */

#include <unistd.h>

/*
 * reads from fd as many times necessary to return exactly 'count' bytes
 */
ssize_t read_bytes(int fd, void *buf, size_t count)
{
	size_t i = 0;
	ssize_t r;

	while (i < count) {
		r = read(fd, buf + i, count - i);
		if (r == 0 || r == -1) {
			if (r == 0) {
#if __DEBUG__
				fprintf(stderr, "EOF or peer has performed socket shutdown.\n");
#endif
			} else {
				perror("read");
			}
			return r;
		}
		i += r;
	}

	return count;
}

#endif
