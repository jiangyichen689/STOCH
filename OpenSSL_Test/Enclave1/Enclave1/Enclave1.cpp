#include "Enclave1_t.h"

#include "sgx_trts.h"

#include <string.h>

void foo(char *buf, size_t len)
{
	const char* secret = "hellow enclave";
	if (len > strlen(secret))
		memcpy(buf, secret, strlen(secret) + 1);
}
