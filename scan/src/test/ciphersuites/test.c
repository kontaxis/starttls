/* kontaxis 2014-10-06 */

#include<stdio.h>

#include "../../ciphersuites.h"

int main (void) {

	uint16_t i;

	fprintf(stdout, "ProtocolVersion version = { %u, %u };\n",
		PROTOCOLMAJOR, PROTOCOLMINOR);

	for (i = 0; i < CIPHERSUITES; i++) {
		fprintf(stdout, "CipherSuite %s = { 0x%02X,0x%02X };\n",
			CIPHER_TXT(CipherSuites[i]), 
			CipherSuites[i] >> 8, CipherSuites[i] & 0xFF);
	}

	return 0;
}
