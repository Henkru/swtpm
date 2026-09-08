/* SPDX-License-Identifier: BSD-3-Clause */
#include <config.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <openssl/evp.h>

#include "lua_intercept.h"
#include "logging.h"
#include "pcap.h"
#include "utils.h"

#define MEMORY_LIMIT (16U * 1024 * 1024)
#define SCRIPT_LIMIT (1024U * 1024)
#define INSTRUCTION_LIMIT 1000000U
#define HOOK_INTERVAL 1000U
#define LOG_LIMIT 4096U

struct bytes {
    unsigned char *data;
    uint32_t length;
};

struct lua_intercept {
    lua_State *L;
    size_t memory;
    unsigned int instructions, logged;
    bool failed, budget_failed, pending, responding, backend_executed;
    int callbacks[2], state_ref;
    uint64_t id, generation, exchange_generation, completed, backend_count;
    uint64_t request_replacements, response_replacements, synthetic_count, errors;
    uint32_t locality, limit, stages;
    struct bytes original, effective, synthetic, final, replacement;
    const unsigned char *input;
    size_t input_length;
    const char *source, *action;
    unsigned char *script;
    size_t script_length;
    int log_fd;
    struct pcap_state backend;
};

static uint32_t load32(const unsigned char *bytes)
{
    return (uint32_t)bytes[0] << 24 | (uint32_t)bytes[1] << 16 |
           (uint32_t)bytes[2] << 8 | bytes[3];
}

static uint64_t monotonic_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

/* All variable strings are represented as hex: diagnostics and script bytes
 * cannot inject records or invalid UTF-8. Metadata strings are C constants. */
static int record(struct lua_intercept *li, const char *stage, const char *origin,
                  const char *action, const void *data, size_t length,
                  uint32_t result)
{
    static const char hex[] = "0123456789abcdef";
    char header[768];
    char *payload = NULL;
    const unsigned char *bytes = data;
    size_t i;
    int n, ret = -1;

    if (li->log_fd < 0)
        return 0;
    n = snprintf(header, sizeof(header),
                 "{\"stage\":\"%s\",\"origin\":\"%s\",\"id\":%" PRIu64
                 ",\"generation\":%" PRIu64 ",\"locality\":%u,"
                 "\"monotonic_ns\":%" PRIu64 ",\"action\":\"%s\","
                 "\"response_source\":\"%s\",\"backend_executed\":%s,"
                 "\"result\":%u,\"buffer_limit\":%u,\"length\":%zu,\"hex\":",
                 stage, origin, !strcmp(origin, "external") ? li->id : 0,
                 li->pending ? li->exchange_generation : li->generation,
                 li->locality, monotonic_ns(), action,
                 li->source ? li->source : "none",
                 li->backend_executed ? "true" : "false", result, li->limit, length);
    if (n < 0 || (size_t)n >= sizeof(header))
        goto error;
    if (data) {
        if (length > (SIZE_MAX - 5) / 2)
            goto error;
        payload = malloc(length * 2 + 5);
        if (!payload)
            goto error;
        payload[0] = '"';
        for (i = 0; i < length; i++) {
            payload[1 + i * 2] = hex[bytes[i] >> 4];
            payload[2 + i * 2] = hex[bytes[i] & 15];
        }
        memcpy(payload + 1 + length * 2, "\"}\n", 4);
    }
    if (write_full(li->log_fd, header, n) != n ||
        write_full(li->log_fd, payload ? payload : "null}\n",
                   payload ? length * 2 + 4 : 6) !=
                   (ssize_t)(payload ? length * 2 + 4 : 6))
        goto error;
    ret = 0;
    goto out;
error:
    li->failed = true;
    li->errors++;
    logprintf(STDERR_FILENO, "Lua interception: cannot write event log\n");
out:
    free(payload);
    return ret;
}

void lua_intercept_fail(struct lua_intercept *li, const char *message)
{
    if (!li)
        return;
    li->failed = true;
    li->errors++;
    logprintf(STDERR_FILENO, "Lua interception: %.4096s\n", message);
    record(li, "error", li->pending ? "external" : "run", "abort",
           message, strnlen(message, LOG_LIMIT), 1);
}

bool lua_intercept_failed(struct lua_intercept *li)
{
    return li && (li->failed || li->backend.failed);
}

void lua_intercept_framing_error(struct lua_intercept *li, const void *bytes, uint32_t length)
{
    record(li, "framing_error", "transport", "reject", bytes, length, 1);
    lua_intercept_fail(li, "invalid, unsupported or truncated raw TPM 2 request");
}

static void *limited_alloc(void *ud, void *ptr, size_t old, size_t size)
{
    struct lua_intercept *li = ud;
    void *res;

    if (!ptr)
        old = 0; /* Lua passes a type tag for new allocations. */
    if (!size) {
        free(ptr);
        li->memory -= old;
        return NULL;
    }
    if (size > MEMORY_LIMIT - (li->memory - old)) {
        li->budget_failed = true;
        return NULL;
    }
    res = realloc(ptr, size);
    if (res)
        li->memory = li->memory - old + size;
    return res;
}

static struct lua_intercept *owner(lua_State *L)
{
    return *(struct lua_intercept **)lua_getextraspace(L);
}

static void instruction_hook(lua_State *L, lua_Debug *ar)
{
    struct lua_intercept *li = owner(L);
    (void)ar;
    li->instructions += HOOK_INTERVAL;
    if (li->instructions >= INSTRUCTION_LIMIT) {
        li->budget_failed = true;
        luaL_error(L, "instruction budget exceeded");
    }
}

static int script_log(lua_State *L)
{
    struct lua_intercept *li = owner(L);
    size_t length;
    const char *s;
    luaL_checktype(L, 1, LUA_TSTRING);
    s = lua_tolstring(L, 1, &length);
    if ((length ? length : 1) > LOG_LIMIT - li->logged)
        return luaL_error(L, "tpm.log budget exceeded (4096 bytes per call)");
    li->logged += length ? length : 1;
    if (record(li, "log", li->pending ? "external" : "run", "log", s, length, 0))
        return luaL_error(L, "tpm.log write failed");
    logprintf(STDERR_FILENO, "Lua: %.*s\n", (int)length, s);
    return 0;
}

/* Keep every allocation and script operation, including context construction
 * and result decoding, inside this protected C trampoline. */
static int protected_call(struct lua_intercept *li, lua_CFunction fn)
{
    int rc;
    lua_State *L = li->L;
    li->instructions = li->logged = 0;
    li->budget_failed = false;
    lua_sethook(L, instruction_hook, LUA_MASKCOUNT, HOOK_INTERVAL);
    lua_pushcfunction(L, fn); /* zero-upvalue C function: does not allocate */
    rc = lua_pcall(L, 0, 0, 0);
    lua_sethook(L, NULL, 0, 0);
    if (rc != LUA_OK || li->budget_failed) {
        const char *message = lua_type(L, -1) == LUA_TSTRING ?
                              lua_tostring(L, -1) : "script failed (non-string error)";
        lua_intercept_fail(li, li->budget_failed ? "Lua execution budget exceeded" : message);
    }
    lua_settop(L, 0);
    return lua_intercept_failed(li) ? -1 : 0;
}

static void rawfield(lua_State *L, int idx, const char *key)
{
    idx = lua_absindex(L, idx);
    lua_pushstring(L, key);
    lua_rawget(L, idx);
}

static int initialize(lua_State *L)
{
    struct lua_intercept *li = owner(L);
    const char *removed[] = {
        "dofile", "loadfile", "load", "collectgarbage", "print", "warn",
        /* No caught budget errors or finalizers that run outside a callback. */
        "pcall", "xpcall", "setmetatable", "getmetatable", NULL
    };
    const char *callbacks[] = { "on_request", "on_response" };
    int i;

    luaL_requiref(L, "_G", luaopen_base, 1);
    lua_pop(L, 1);
    for (i = 0; removed[i]; i++) {
        lua_pushnil(L);
        lua_setglobal(L, removed[i]);
    }
    luaL_requiref(L, LUA_STRLIBNAME, luaopen_string, 1);
    lua_pop(L, 1);
    luaL_requiref(L, LUA_TABLIBNAME, luaopen_table, 1);
    lua_pop(L, 1);
    luaL_requiref(L, LUA_MATHLIBNAME, luaopen_math, 1);
    lua_pop(L, 1);
    lua_newtable(L);
    lua_pushcfunction(L, script_log);
    lua_setfield(L, -2, "log");
    lua_setglobal(L, "tpm");

    if (luaL_loadbufferx(L, (const char *)li->script, li->script_length,
                         "@attack.lua", "t") != LUA_OK)
        return lua_error(L);
    lua_call(L, 0, 1);
    luaL_checktype(L, -1, LUA_TTABLE);
    rawfield(L, -1, "api_version");
    if (!lua_isinteger(L, -1) || lua_tointeger(L, -1) != 1)
        return luaL_error(L, "script must return api_version = 1");
    lua_pop(L, 1);
    for (i = 0; i < 2; i++) {
        rawfield(L, -1, callbacks[i]);
        if (!lua_isnil(L, -1) && !lua_isfunction(L, -1))
            return luaL_error(L, "%s must be a function", callbacks[i]);
        li->callbacks[i] = luaL_ref(L, LUA_REGISTRYINDEX);
    }
    if (li->callbacks[0] == LUA_REFNIL && li->callbacks[1] == LUA_REFNIL)
        return luaL_error(L, "script must provide on_request or on_response");
    return 0;
}

static int copy_bytes(struct bytes *dest, const void *data, size_t length)
{
    dest->data = malloc(length ? length : 1);
    if (!dest->data)
        return -1;
    if (length)
        memcpy(dest->data, data, length);
    dest->length = length;
    return 0;
}

static void set_integer(lua_State *L, const char *key, lua_Integer value)
{
    lua_pushinteger(L, value);
    lua_setfield(L, -2, key);
}

static int invoke(lua_State *L)
{
    struct lua_intercept *li = owner(L);
    const char *action, *data;
    size_t length, action_length;
    int callback = li->callbacks[li->responding];
    bool valid_tag;

    if (!li->responding) {
        lua_newtable(L);
        li->state_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    }
    if (callback == LUA_REFNIL)
        return 0;
    lua_rawgeti(L, LUA_REGISTRYINDEX, callback);
    lua_newtable(L);
    set_integer(L, "id", li->id);
    set_integer(L, "generation", li->exchange_generation);
    set_integer(L, "tpm_version", 2);
    set_integer(L, "locality", li->locality);
    set_integer(L, "command_code", load32(li->original.data + 6));
    lua_rawgeti(L, LUA_REGISTRYINDEX, li->state_ref);
    lua_setfield(L, -2, "state");
    lua_pushlstring(L, (const char *)li->original.data, li->original.length);
    lua_setfield(L, -2, "original_request");
    if (li->responding) {
        if (li->effective.data) {
            lua_pushlstring(L, (const char *)li->effective.data, li->effective.length);
            lua_setfield(L, -2, "effective_request");
            set_integer(L, "effective_command_code", load32(li->effective.data + 6));
        }
        lua_pushboolean(L, li->backend_executed);
        lua_setfield(L, -2, "backend_executed");
        lua_pushstring(L, li->source);
        lua_setfield(L, -2, "response_source");
    }
    lua_pushlstring(L, (const char *)li->input, li->input_length);
    lua_call(L, 2, 1);
    if (lua_isnil(L, -1))
        return 0;
    luaL_checktype(L, -1, LUA_TTABLE);
    rawfield(L, -1, "action");
    luaL_checktype(L, -1, LUA_TSTRING);
    action = lua_tolstring(L, -1, &action_length);
    if (action_length == 4 && !memcmp(action, "pass", 4))
        return 0;
    if (action_length == 7 && !memcmp(action, "replace", 7))
        li->action = "replace";
    else if (!li->responding && action_length == 7 && !memcmp(action, "respond", 7))
        li->action = "respond";
    else
        return luaL_error(L, "invalid interception action");
    lua_pop(L, 1);
    rawfield(L, -1, "bytes");
    luaL_checktype(L, -1, LUA_TSTRING);
    data = lua_tolstring(L, -1, &length);
    if (length < 10 || length > li->limit)
        return luaL_error(L, "replacement has invalid TPM 2 framing or exceeds buffer limit");
    valid_tag = (unsigned char)data[0] == 0x80 && (data[1] == 1 || data[1] == 2);
    /* TPM 2 uses the legacy response tag specifically for TPM_RC_BAD_TAG. */
    if ((li->responding || !strcmp(li->action, "respond")) &&
        data[0] == 0 && (unsigned char)data[1] == 0xc4 && length == 10 &&
        load32((const unsigned char *)data + 6) == 0x1e)
        valid_tag = true;
    if (!valid_tag || load32((const unsigned char *)data + 2) != length)
        return luaL_error(L, "replacement has invalid TPM 2 framing or exceeds buffer limit");
    if (copy_bytes(&li->replacement, data, length))
        return luaL_error(L, "cannot allocate replacement buffer");
    return 0;
}

void lua_intercept_processed(struct lua_intercept *li, uint32_t result)
{
    if (!li)
        return;
    li->backend_executed = true;
    li->source = "tpm";
    record(li, "processing", "external", result ? "failed" : "executed", NULL, 0, result);
}

static int release_state(lua_State *L)
{
    struct lua_intercept *li = owner(L);
    luaL_unref(L, LUA_REGISTRYINDEX, li->state_ref);
    li->state_ref = LUA_NOREF;
    return 0;
}

static void free_exchange(struct lua_intercept *li)
{
    struct bytes *buffers[] = { &li->original, &li->effective, &li->synthetic,
                               &li->final, &li->replacement };
    size_t i;
    if (li->L && li->state_ref != LUA_NOREF)
        protected_call(li, release_state);
    li->state_ref = LUA_NOREF;
    for (i = 0; i < sizeof(buffers) / sizeof(buffers[0]); i++) {
        free(buffers[i]->data);
        *buffers[i] = (struct bytes){0};
    }
    li->pending = false;
}

void lua_intercept_complete(struct lua_intercept *li, uint32_t result)
{
    const char *stages[] = { "original_request", "effective_request",
                            "original_response", "final_response" };
    unsigned int i;
    if (!li || !li->pending)
        return;
    for (i = 0; i < 4; i++) {
        if (!(li->stages & (1U << i)))
            record(li, stages[i], "external", "absent", NULL, 0, result);
    }
    record(li, "complete", "external", result ? "failed" : "written",
           NULL, 0, result);
    li->completed++;
    free_exchange(li);
}

int lua_intercept_request(struct lua_intercept *li, const unsigned char *request,
                          uint32_t length, uint32_t locality, uint32_t limit,
                          unsigned char **effective, uint32_t *effective_length,
                          bool *synthetic)
{
    if (!li)
        return 0;
    if (li->pending || li->id >= LUA_MAXINTEGER) {
        lua_intercept_fail(li, "invalid exchange lifetime or exhausted IDs");
        return -1;
    }
    li->id++;
    li->pending = true;
    li->responding = li->backend_executed = false;
    li->source = "none";
    li->action = "pass";
    li->exchange_generation = li->generation;
    li->locality = locality;
    li->limit = limit;
    li->stages = 1;
    if (record(li, "original_request", "external", "accept", request, length, 0))
        return -1;
    if (copy_bytes(&li->original, request, length)) {
        lua_intercept_fail(li, "cannot allocate original request");
        return -1;
    }
    li->input = request;
    li->input_length = length;
    if (protected_call(li, invoke))
        return -1;
    *synthetic = !strcmp(li->action, "respond");
    if (*synthetic) {
        li->synthetic = li->replacement;
        li->synthetic_count++;
    } else if (li->replacement.data) {
        li->effective = li->replacement;
        li->request_replacements++;
    } else if (copy_bytes(&li->effective, request, length)) {
        lua_intercept_fail(li, "cannot allocate effective request");
        return -1;
    }
    li->replacement = (struct bytes){0};
    *effective = li->effective.data;
    *effective_length = li->effective.length;
    li->stages |= 2;
    return record(li, "effective_request", "external", li->action,
                  li->effective.data, li->effective.length, 0);
}

const unsigned char *lua_intercept_synthetic(struct lua_intercept *li, uint32_t *length)
{
    *length = li->synthetic.length;
    return li->synthetic.data;
}

int lua_intercept_response(struct lua_intercept *li, const unsigned char *response,
                           uint32_t length, bool backend_executed,
                           const char *source, unsigned char **final,
                           uint32_t *final_length)
{
    if (!li)
        return 0;
    li->responding = true;
    li->backend_executed = backend_executed;
    li->source = source;
    li->action = "pass";
    li->stages |= 4;
    if (record(li, "original_response", "external", "produce", response, length, 0))
        return -1;
    li->input = response;
    li->input_length = length;
    if (protected_call(li, invoke))
        return -1;
    if (li->replacement.data) {
        li->final = li->replacement;
        li->response_replacements++;
        li->replacement = (struct bytes){0};
    } else if (copy_bytes(&li->final, response, length)) {
        lua_intercept_fail(li, "cannot allocate final response");
        return -1;
    }
    *final = li->final.data;
    *final_length = li->final.length;
    li->stages |= 8;
    return record(li, "final_response", "external", li->action,
                  li->final.data, li->final.length, 0);
}

int lua_intercept_backend(struct lua_intercept *li, unsigned char *bytes,
                          uint32_t length, bool request)
{
    if (!li)
        return 0;
    if (pcap_packet_record_write(&li->backend, bytes, length, request)) {
        lua_intercept_fail(li, "cannot write backend capture");
        return -1;
    }
    if (!request)
        li->backend_count++;
    return 0;
}

int lua_intercept_internal(struct lua_intercept *li, const void *bytes,
                            uint32_t length, bool request, uint32_t result)
{
    if (li)
        return record(li, request ? "request" : "response", "internal", "bypass",
                      bytes, length, result);
    return 0;
}

void lua_intercept_initialized(struct lua_intercept *li)
{
    if (!li)
        return;
    if (li->generation >= LUA_MAXINTEGER) {
        lua_intercept_fail(li, "initialization generation exhausted");
        return;
    }
    li->generation++;
    record(li, "initialized", "control", "init", NULL, 0, 0);
}

static int duplicate_fd(int fd, bool writable)
{
    int flags = fcntl(fd, F_GETFL);
    struct stat st;
    if (fd < 3 || flags < 0 ||
        (writable ? (flags & O_ACCMODE) == O_RDONLY : (flags & O_ACCMODE) == O_WRONLY))
        return -1;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode))
        return -1;
    return fcntl(fd, F_DUPFD_CLOEXEC, 3);
}

static bool same_file(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

int lua_intercept_open(struct lua_intercept **out, const char *path,
                       int script_fd, int log_fd, int pcap_fd, int native_fd)
{
    struct lua_intercept *li = calloc(1, sizeof(*li));
    int fd = -1, ret = -1;
    ssize_t n;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_length;
    char hash[65], manifest[1024];
    size_t i;

    if (!li)
        return -1;
    *out = li; /* cleanup also retains startup failure records */
    li->log_fd = -1;
    li->state_ref = LUA_NOREF;
    pcap_state_init(&li->backend);
    if ((path && script_fd >= 0) || (!path && script_fd < 0) ||
        (log_fd >= 0 && (log_fd == script_fd || log_fd == pcap_fd)) ||
        (pcap_fd >= 0 && pcap_fd == script_fd))
        goto error;
    if (log_fd >= 0 && (li->log_fd = duplicate_fd(log_fd, true)) < 0)
        goto error;
    if (pcap_fd >= 0) {
        li->backend.fd = duplicate_fd(pcap_fd, true);
        if (li->backend.fd < 0)
            goto error;
    }
    fd = path ? open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK) : duplicate_fd(script_fd, false);
    if (fd < 0)
        goto error;
    /* Sources must be snapshots, not a potentially blocking stream. */
    {
        struct stat st, log_st = {0}, pcap_st = {0}, native_st = {0};
        if (fstat(fd, &st) || !S_ISREG(st.st_mode) ||
            (li->log_fd >= 0 && fstat(li->log_fd, &log_st)) ||
            (li->backend.fd >= 0 && fstat(li->backend.fd, &pcap_st)) ||
            (native_fd >= 0 && fstat(native_fd, &native_st)))
            goto error;
        if ((li->log_fd >= 0 && same_file(&st, &log_st)) ||
            (li->backend.fd >= 0 && same_file(&st, &pcap_st)) ||
            (li->log_fd >= 0 && li->backend.fd >= 0 &&
             same_file(&log_st, &pcap_st)) ||
            (native_fd >= 0 && (
             same_file(&native_st, &st) ||
             (li->log_fd >= 0 && same_file(&native_st, &log_st)) ||
             (li->backend.fd >= 0 && same_file(&native_st, &pcap_st))))) {
            /* Do not write diagnostics or a TCP trailer into an aliased file. */
            if (li->log_fd >= 0)
                close(li->log_fd);
            if (li->backend.fd >= 0)
                close(li->backend.fd);
            li->log_fd = li->backend.fd = -1;
            goto error;
        }
    }
    if (li->backend.fd >= 0 && pcap_file_new(&li->backend))
        goto error;
    li->script = malloc(SCRIPT_LIMIT + 1);
    if (!li->script)
        goto error;
    while (li->script_length <= SCRIPT_LIMIT) {
        n = read(fd, li->script + li->script_length, SCRIPT_LIMIT + 1 - li->script_length);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0)
            goto error;
        if (!n)
            break;
        li->script_length += n;
    }
    if (close(fd)) {
        fd = -1;
        goto error;
    }
    fd = -1;
    if (li->script_length > SCRIPT_LIMIT ||
        !EVP_Digest(li->script, li->script_length, digest, &digest_length, EVP_sha256(), NULL) ||
        digest_length != 32)
        goto error;
    for (i = 0; i < 32; i++)
        snprintf(hash + 2 * i, 3, "%02x", digest[i]);
    n = snprintf(manifest, sizeof(manifest),
                 "{\"stage\":\"manifest\",\"api_version\":1,\"lua_version\":\"%s\","
                 "\"swtpm_version\":\"%s\",\"source_revision\":\"%s\","
                 "\"run_id\":\"%ld-%" PRIu64 "\",\"script_sha256\":\"%s\","
                 "\"memory_limit\":%u,\"instruction_limit\":%u,\"script_limit\":%u,"
                 "\"log_limit\":%u,\"native_boundary\":\"external-original-request/final-response-and-internal\","
                 "\"backend_boundary\":\"external-TPMLIB_Process-only\"}\n",
                 LUA_RELEASE, VERSION, SWTPM_SOURCE_REVISION, (long)getpid(), monotonic_ns(),
                 hash, MEMORY_LIMIT, INSTRUCTION_LIMIT, SCRIPT_LIMIT, LOG_LIMIT);
    if (n < 0 || (size_t)n >= sizeof(manifest) ||
        (li->log_fd >= 0 && write_full(li->log_fd, manifest, n) != n))
        goto error;
    if (record(li, "script", "run", "snapshot", li->script, li->script_length, 0))
        goto error;
    li->L = lua_newstate(limited_alloc, li);
    if (!li->L)
        goto error;
    *(struct lua_intercept **)lua_getextraspace(li->L) = li;
    ret = protected_call(li, initialize);
    free(li->script);
    li->script = NULL;
    return ret;
error:
    if (fd >= 0)
        close(fd);
    lua_intercept_fail(li, "cannot initialize script/artifacts (invalid FD, source, size, allocation or write)");
    return -1;
}

int lua_intercept_close(struct lua_intercept *li)
{
    char summary[512];
    int n, ret;
    if (!li)
        return 0;
    if (li->pending) {
        lua_intercept_fail(li, "exchange aborted before completion");
        lua_intercept_complete(li, 1);
    }
    if (pcap_state_fd_close(&li->backend))
        lua_intercept_fail(li, "cannot close backend capture");
    if (li->L)
        lua_close(li->L);
    free(li->script);
    n = snprintf(summary, sizeof(summary),
                 "{\"stage\":\"run_complete\",\"exchanges\":%" PRIu64
                 ",\"completed\":%" PRIu64 ",\"backend_exchanges\":%" PRIu64
                 ",\"request_replacements\":%" PRIu64 ",\"response_replacements\":%" PRIu64
                 ",\"synthetic_exchanges\":%" PRIu64 ",\"errors\":%" PRIu64
                 ",\"failed\":%s}\n", li->id, li->completed, li->backend_count,
                 li->request_replacements, li->response_replacements, li->synthetic_count, li->errors,
                 li->failed ? "true" : "false");
    if (li->log_fd >= 0) {
        if (write_full(li->log_fd, summary, n) != n)
            li->failed = true;
        if (close(li->log_fd))
            li->failed = true;
    }
    ret = li->failed ? -1 : 0;
    if (ret)
        logprintf(STDERR_FILENO, "Lua interception run failed; retain partial artifacts\n");
    free(li);
    return ret;
}
