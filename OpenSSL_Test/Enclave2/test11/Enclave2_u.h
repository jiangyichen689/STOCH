#ifndef ENCLAVE2_U_H__
#define ENCLAVE2_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxssl_ftime64, (void* timeptr, uint32_t timeb64Len));
int SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxssl_closesocket, (void* s, int* wsaError));
int SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxssl_recv, (void* s, void* buf, int len, int flag, int* wsaError));
int SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxssl_send, (void* s, const char* buf, int len, int flags, int* wsaError));
int SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxssl_shutdown, (void* s, int how, int* wsaError));
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));

sgx_status_t generateKey(sgx_enclave_id_t eid, char* publicKey, size_t publicKeyLen);
sgx_status_t sendStruct(sgx_enclave_id_t eid, char* buf, size_t lenOfString);
sgx_status_t Query(sgx_enclave_id_t eid, char* query, size_t len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
