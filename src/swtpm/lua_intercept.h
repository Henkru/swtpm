/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef SWTPM_LUA_INTERCEPT_H
#define SWTPM_LUA_INTERCEPT_H

#include <stdbool.h>
#include <stdint.h>

struct lua_intercept;

#ifdef WITH_LUA
/* Input descriptors remain owned by the caller; the bridge duplicates them.
 * The exact text snapshot (at most 1 MiB) is hashed, logged, and loaded once. */
int lua_intercept_open(struct lua_intercept **li, const char *path,
                       int script_fd, int log_fd, int pcap_fd, int native_fd);
int lua_intercept_close(struct lua_intercept *li);
bool lua_intercept_failed(struct lua_intercept *li);
void lua_intercept_fail(struct lua_intercept *li, const char *message);
void lua_intercept_framing_error(struct lua_intercept *li, const void *bytes, uint32_t length);
void lua_intercept_initialized(struct lua_intercept *li);
int lua_intercept_request(struct lua_intercept *li, const unsigned char *request,
                          uint32_t length, uint32_t locality, uint32_t limit,
                          unsigned char **effective, uint32_t *effective_length,
                          bool *synthetic);
const unsigned char *lua_intercept_synthetic(struct lua_intercept *li,
                                            uint32_t *length);
int lua_intercept_response(struct lua_intercept *li, const unsigned char *response,
                           uint32_t length, bool backend_executed,
                           const char *source, unsigned char **final,
                           uint32_t *final_length);
int lua_intercept_backend(struct lua_intercept *li, unsigned char *bytes,
                          uint32_t length, bool request);
void lua_intercept_processed(struct lua_intercept *li, uint32_t result);
void lua_intercept_complete(struct lua_intercept *li, uint32_t result);
int lua_intercept_internal(struct lua_intercept *li, const void *bytes,
                            uint32_t length, bool request, uint32_t result);
#else
#define lua_intercept_close(li) 0
#define lua_intercept_failed(li) false
#define lua_intercept_fail(li, message) ((void)0)
#define lua_intercept_framing_error(li, bytes, length) ((void)0)
#define lua_intercept_initialized(li) ((void)0)
#define lua_intercept_request(li, req, len, loc, limit, eff, elen, syn) 0
#define lua_intercept_synthetic(li, len) NULL
#define lua_intercept_response(li, resp, len, executed, source, final, flen) \
    ((void)(executed), (void)(source), 0)
#define lua_intercept_backend(li, bytes, len, request) 0
#define lua_intercept_processed(li, result) ((void)0)
#define lua_intercept_complete(li, result) ((void)0)
#define lua_intercept_internal(li, bytes, len, request, result) 0
#endif

#endif
