#include<stdio.h>
#include<tchar.h>
#include "sgx_urts.h"
#include "Enclave2_u.h"
#include <windows.h>

#define ENCLAVE_FILE _T("Enclave2.signed.dll")
#define MAX_BUF_LEN 100

int main()
{
	sgx_enclave_id_t eid;
	sgx_status_t   ret = SGX_SUCCESS;
	sgx_launch_token_t token = { 0 };

	int update = 0;
	char buffer[MAX_BUF_LEN] = "hello world";

	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &update, &eid, NULL);
	foo(eid, buffer, MAX_BUF_LEN);
	printf("%s\n", buffer);

	if (SGX_SUCCESS != sgx_destroy_enclave(eid))
		return -1;
	return 0;
}