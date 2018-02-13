#include "Enclave2_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#endif

static sgx_status_t SGX_CDECL sgx_generateKey(void* pms)
{
	ms_generateKey_t* ms = SGX_CAST(ms_generateKey_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_publicKey = ms->ms_publicKey;
	size_t _tmp_publicKeyLen = ms->ms_publicKeyLen;
	size_t _len_publicKey = _tmp_publicKeyLen;
	char* _in_publicKey = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_generateKey_t));
	CHECK_UNIQUE_POINTER(_tmp_publicKey, _len_publicKey);

	if (_tmp_publicKey != NULL) {
		if ((_in_publicKey = (char*)malloc(_len_publicKey)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_publicKey, 0, _len_publicKey);
	}
	generateKey(_in_publicKey, _tmp_publicKeyLen);
err:
	if (_in_publicKey) {
		memcpy(_tmp_publicKey, _in_publicKey, _len_publicKey);
		free(_in_publicKey);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_sendStruct(void* pms)
{
	ms_sendStruct_t* ms = SGX_CAST(ms_sendStruct_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_buf = ms->ms_buf;
	size_t _tmp_lenOfString = ms->ms_lenOfString;
	size_t _len_buf = _tmp_lenOfString;
	char* _in_buf = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_sendStruct_t));
	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	if (_tmp_buf != NULL) {
		_in_buf = (char*)malloc(_len_buf);
		if (_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_buf, _tmp_buf, _len_buf);
	}
	sendStruct(_in_buf, _tmp_lenOfString);
err:
	if (_in_buf) {
		memcpy(_tmp_buf, _in_buf, _len_buf);
		free(_in_buf);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_Query(void* pms)
{
	ms_Query_t* ms = SGX_CAST(ms_Query_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_query = ms->ms_query;
	size_t _tmp_len = ms->ms_len;
	size_t _len_query = _tmp_len;
	char* _in_query = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_Query_t));
	CHECK_UNIQUE_POINTER(_tmp_query, _len_query);

	if (_tmp_query != NULL) {
		_in_query = (char*)malloc(_len_query);
		if (_in_query == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_query, _tmp_query, _len_query);
	}
	Query(_in_query, _tmp_len);
err:
	if (_in_query) {
		memcpy(_tmp_query, _in_query, _len_query);
		free(_in_query);
	}

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv;} ecall_table[3];
} g_ecall_table = {
	3,
	{
		{(void*)(uintptr_t)sgx_generateKey, 0},
		{(void*)(uintptr_t)sgx_sendStruct, 0},
		{(void*)(uintptr_t)sgx_Query, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[10][3];
} g_dyn_entry_table = {
	10,
	{
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL u_sgxssl_ftime64(void* timeptr, uint32_t timeb64Len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_timeptr = timeb64Len;

	ms_u_sgxssl_ftime64_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxssl_ftime64_t);
	void *__tmp = NULL;

	ocalloc_size += (timeptr != NULL && sgx_is_within_enclave(timeptr, _len_timeptr)) ? _len_timeptr : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxssl_ftime64_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxssl_ftime64_t));

	if (timeptr != NULL && sgx_is_within_enclave(timeptr, _len_timeptr)) {
		ms->ms_timeptr = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_timeptr);
		memset(ms->ms_timeptr, 0, _len_timeptr);
	} else if (timeptr == NULL) {
		ms->ms_timeptr = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_timeb64Len = timeb64Len;
	status = sgx_ocall(0, ms);

	if (timeptr) memcpy((void*)timeptr, ms->ms_timeptr, _len_timeptr);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxssl_closesocket(int* retval, void* s, int* wsaError)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_wsaError = sizeof(*wsaError);

	ms_u_sgxssl_closesocket_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxssl_closesocket_t);
	void *__tmp = NULL;

	ocalloc_size += (wsaError != NULL && sgx_is_within_enclave(wsaError, _len_wsaError)) ? _len_wsaError : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxssl_closesocket_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxssl_closesocket_t));

	ms->ms_s = SGX_CAST(void*, s);
	if (wsaError != NULL && sgx_is_within_enclave(wsaError, _len_wsaError)) {
		ms->ms_wsaError = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_wsaError);
		memset(ms->ms_wsaError, 0, _len_wsaError);
	} else if (wsaError == NULL) {
		ms->ms_wsaError = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(1, ms);

	if (retval) *retval = ms->ms_retval;
	if (wsaError) memcpy((void*)wsaError, ms->ms_wsaError, _len_wsaError);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxssl_recv(int* retval, void* s, void* buf, int len, int flag, int* wsaError)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = len;
	size_t _len_wsaError = sizeof(*wsaError);

	ms_u_sgxssl_recv_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxssl_recv_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;
	ocalloc_size += (wsaError != NULL && sgx_is_within_enclave(wsaError, _len_wsaError)) ? _len_wsaError : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxssl_recv_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxssl_recv_t));

	ms->ms_s = SGX_CAST(void*, s);
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memset(ms->ms_buf, 0, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	ms->ms_flag = flag;
	if (wsaError != NULL && sgx_is_within_enclave(wsaError, _len_wsaError)) {
		ms->ms_wsaError = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_wsaError);
		memset(ms->ms_wsaError, 0, _len_wsaError);
	} else if (wsaError == NULL) {
		ms->ms_wsaError = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(2, ms);

	if (retval) *retval = ms->ms_retval;
	if (buf) memcpy((void*)buf, ms->ms_buf, _len_buf);
	if (wsaError) memcpy((void*)wsaError, ms->ms_wsaError, _len_wsaError);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxssl_send(int* retval, void* s, const char* buf, int len, int flags, int* wsaError)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = len;
	size_t _len_wsaError = sizeof(*wsaError);

	ms_u_sgxssl_send_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxssl_send_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;
	ocalloc_size += (wsaError != NULL && sgx_is_within_enclave(wsaError, _len_wsaError)) ? _len_wsaError : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxssl_send_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxssl_send_t));

	ms->ms_s = SGX_CAST(void*, s);
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memcpy((void*)ms->ms_buf, buf, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	ms->ms_flags = flags;
	if (wsaError != NULL && sgx_is_within_enclave(wsaError, _len_wsaError)) {
		ms->ms_wsaError = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_wsaError);
		memset(ms->ms_wsaError, 0, _len_wsaError);
	} else if (wsaError == NULL) {
		ms->ms_wsaError = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(3, ms);

	if (retval) *retval = ms->ms_retval;
	if (wsaError) memcpy((void*)wsaError, ms->ms_wsaError, _len_wsaError);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxssl_shutdown(int* retval, void* s, int how, int* wsaError)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_wsaError = sizeof(*wsaError);

	ms_u_sgxssl_shutdown_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxssl_shutdown_t);
	void *__tmp = NULL;

	ocalloc_size += (wsaError != NULL && sgx_is_within_enclave(wsaError, _len_wsaError)) ? _len_wsaError : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxssl_shutdown_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxssl_shutdown_t));

	ms->ms_s = SGX_CAST(void*, s);
	ms->ms_how = how;
	if (wsaError != NULL && sgx_is_within_enclave(wsaError, _len_wsaError)) {
		ms->ms_wsaError = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_wsaError);
		memset(ms->ms_wsaError, 0, _len_wsaError);
	} else if (wsaError == NULL) {
		ms->ms_wsaError = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(4, ms);

	if (retval) *retval = ms->ms_retval;
	if (wsaError) memcpy((void*)wsaError, ms->ms_wsaError, _len_wsaError);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(*cpuinfo);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	ocalloc_size += (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) ? _len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));

	if (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		memcpy(ms->ms_cpuinfo, cpuinfo, _len_cpuinfo);
	} else if (cpuinfo == NULL) {
		ms->ms_cpuinfo = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(5, ms);

	if (cpuinfo) memcpy((void*)cpuinfo, ms->ms_cpuinfo, _len_cpuinfo);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));

	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(6, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	status = sgx_ocall(7, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(8, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(*waiters);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));

	if (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) {
		ms->ms_waiters = (void**)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		memcpy((void*)ms->ms_waiters, waiters, _len_waiters);
	} else if (waiters == NULL) {
		ms->ms_waiters = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(9, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
