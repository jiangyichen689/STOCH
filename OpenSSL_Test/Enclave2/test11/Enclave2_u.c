#include "Enclave2_u.h"
#include <errno.h>

typedef struct ms_generateKey_t {
	char* ms_publicKey;
	size_t ms_publicKeyLen;
} ms_generateKey_t;

typedef struct ms_sendStruct_t {
	char* ms_buf;
	size_t ms_lenOfString;
} ms_sendStruct_t;

typedef struct ms_Query_t {
	char* ms_query;
	size_t ms_len;
} ms_Query_t;

typedef struct ms_u_sgxssl_ftime64_t {
	void* ms_timeptr;
	uint32_t ms_timeb64Len;
} ms_u_sgxssl_ftime64_t;

typedef struct ms_u_sgxssl_closesocket_t {
	int ms_retval;
	void* ms_s;
	int* ms_wsaError;
} ms_u_sgxssl_closesocket_t;

typedef struct ms_u_sgxssl_recv_t {
	int ms_retval;
	void* ms_s;
	void* ms_buf;
	int ms_len;
	int ms_flag;
	int* ms_wsaError;
} ms_u_sgxssl_recv_t;

typedef struct ms_u_sgxssl_send_t {
	int ms_retval;
	void* ms_s;
	char* ms_buf;
	int ms_len;
	int ms_flags;
	int* ms_wsaError;
} ms_u_sgxssl_send_t;

typedef struct ms_u_sgxssl_shutdown_t {
	int ms_retval;
	void* ms_s;
	int ms_how;
	int* ms_wsaError;
} ms_u_sgxssl_shutdown_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL Enclave2_u_sgxssl_ftime64(void* pms)
{
	ms_u_sgxssl_ftime64_t* ms = SGX_CAST(ms_u_sgxssl_ftime64_t*, pms);
	u_sgxssl_ftime64(ms->ms_timeptr, ms->ms_timeb64Len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave2_u_sgxssl_closesocket(void* pms)
{
	ms_u_sgxssl_closesocket_t* ms = SGX_CAST(ms_u_sgxssl_closesocket_t*, pms);
	ms->ms_retval = u_sgxssl_closesocket(ms->ms_s, ms->ms_wsaError);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave2_u_sgxssl_recv(void* pms)
{
	ms_u_sgxssl_recv_t* ms = SGX_CAST(ms_u_sgxssl_recv_t*, pms);
	ms->ms_retval = u_sgxssl_recv(ms->ms_s, ms->ms_buf, ms->ms_len, ms->ms_flag, ms->ms_wsaError);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave2_u_sgxssl_send(void* pms)
{
	ms_u_sgxssl_send_t* ms = SGX_CAST(ms_u_sgxssl_send_t*, pms);
	ms->ms_retval = u_sgxssl_send(ms->ms_s, (const char*)ms->ms_buf, ms->ms_len, ms->ms_flags, ms->ms_wsaError);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave2_u_sgxssl_shutdown(void* pms)
{
	ms_u_sgxssl_shutdown_t* ms = SGX_CAST(ms_u_sgxssl_shutdown_t*, pms);
	ms->ms_retval = u_sgxssl_shutdown(ms->ms_s, ms->ms_how, ms->ms_wsaError);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave2_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave2_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall((const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave2_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall((const void*)ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave2_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall((const void*)ms->ms_waiter, (const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave2_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall((const void**)ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[10];
} ocall_table_Enclave2 = {
	10,
	{
		(void*)(uintptr_t)Enclave2_u_sgxssl_ftime64,
		(void*)(uintptr_t)Enclave2_u_sgxssl_closesocket,
		(void*)(uintptr_t)Enclave2_u_sgxssl_recv,
		(void*)(uintptr_t)Enclave2_u_sgxssl_send,
		(void*)(uintptr_t)Enclave2_u_sgxssl_shutdown,
		(void*)(uintptr_t)Enclave2_sgx_oc_cpuidex,
		(void*)(uintptr_t)Enclave2_sgx_thread_wait_untrusted_event_ocall,
		(void*)(uintptr_t)Enclave2_sgx_thread_set_untrusted_event_ocall,
		(void*)(uintptr_t)Enclave2_sgx_thread_setwait_untrusted_events_ocall,
		(void*)(uintptr_t)Enclave2_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};

sgx_status_t generateKey(sgx_enclave_id_t eid, char* publicKey, size_t publicKeyLen)
{
	sgx_status_t status;
	ms_generateKey_t ms;
	ms.ms_publicKey = publicKey;
	ms.ms_publicKeyLen = publicKeyLen;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave2, &ms);
	return status;
}

sgx_status_t sendStruct(sgx_enclave_id_t eid, char* buf, size_t lenOfString)
{
	sgx_status_t status;
	ms_sendStruct_t ms;
	ms.ms_buf = buf;
	ms.ms_lenOfString = lenOfString;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave2, &ms);
	return status;
}

sgx_status_t Query(sgx_enclave_id_t eid, char* query, size_t len)
{
	sgx_status_t status;
	ms_Query_t ms;
	ms.ms_query = query;
	ms.ms_len = len;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave2, &ms);
	return status;
}

