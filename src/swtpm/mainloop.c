/*
 * mainloop.c -- The TPM Emulator's main processing loop
 *
 * (c) Copyright IBM Corporation 2014, 2015, 2016
 *
 * Author: Stefan Berger <stefanb@us.ibm.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * Neither the names of the IBM Corporation nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* mainLoop() is the main server loop.

   It reads a TPM request, processes the ordinal, and writes the response
*/

#include <config.h>

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>

#include <libtpms/tpm_error.h>
#include <libtpms/tpm_library.h>
#include <libtpms/tpm_memory.h>

#include "swtpm_debug.h"
#include "swtpm_io.h"
#include "tpmlib.h"
#include "locality.h"
#include "logging.h"
#include "ctrlchannel.h"
#include "mainloop.h"
#include "utils.h"
#include "sys_dependencies.h"
#include "compiler_dependencies.h"
#include "swtpm_utils.h"
#include "swtpm_nvstore.h"

/* local variables */
static TPM_MODIFIER_INDICATOR g_locality;

bool g_mainloop_terminate;

TPM_RESULT
mainloop_cb_get_locality(TPM_MODIFIER_INDICATOR *loc,
                         uint32_t tpmnum SWTPM_ATTR_UNUSED)
{
    *loc = g_locality;

    return TPM_SUCCESS;
}

/* ensure that the storage is locked; returns false in case of failure */
bool mainloop_ensure_locked_storage(struct mainLoopParams *mlp)
{
    TPM_RESULT res;

    if (mlp->storage_locked)
        return true;

    /* if NVRAM hasn't been initialized yet locking may need to be retried */
    res = SWTPM_NVRAM_Lock_Storage(mlp->locking_retries);
    if (res == TPM_RETRY)
        return true;
    if (res != TPM_SUCCESS)
        return false;

    mlp->locking_retries = 0;
    mlp->storage_locked = true;
    mlp->incoming_migration = false;

    return true;
}

void mainloop_unlock_nvram(struct mainLoopParams *mlp,
                           unsigned int locking_retries)
{
    SWTPM_NVRAM_Unlock();

    mlp->storage_locked = false;
    mlp->locking_retries = locking_retries;
}

#ifdef WITH_LUA
struct lua_transmit_context {
    struct mainLoopParams *mlp;
    const bool *tpm_running;
};

static uint32_t mainloop_lua_transmit(void *opaque, unsigned char *command,
                                     uint32_t length, unsigned char **response,
                                     uint32_t *response_length, bool *executed)
{
    struct lua_transmit_context *ctx = opaque;
    uint32_t capacity = 0;
    uint32_t ordinal;

    /* on_request runs before the external command's readiness checks. */
    if (!*ctx->tpm_running) {
        lua_intercept_fail(ctx->mlp->lua, "tpm.transmit: TPM is not running");
        return TPM_FAIL;
    }
    if (!mainloop_ensure_locked_storage(ctx->mlp)) {
        lua_intercept_fail(ctx->mlp->lua, "tpm.transmit: cannot lock TPM storage");
        return TPM_FAIL;
    }

    ordinal = tpmlib_get_cmd_ordinal(command, length);
    if (ordinal != TPM_ORDINAL_NONE)
        ctx->mlp->lastCommand = ordinal;
    *executed = true;
    /* Inherit g_locality. Bypass both interception and swtpm-local commands;
     * private buffers preserve the response currently being intercepted. */
    return TPMLIB_Process(response, response_length, &capacity, command, length);
}
#endif

int mainLoop(struct mainLoopParams *mlp, int notify_fd, bool tpm_running)
{
    TPM_RESULT          rc = 0;
    TPM_CONNECTION_FD   connection_fd;             /* file descriptor for read/write */
    unsigned char       *command = NULL;           /* command buffer */
    uint32_t            command_length = 0;        /* actual length of command bytes */
    uint32_t            max_command_length;        /* command buffer size */
    off_t               cmd_offset;
    /* The response buffer is reused for each command. Thus it can grow but never shrink */
    unsigned char       *rbuffer = NULL;           /* actual response bytes */
    uint32_t            rlength = 0;               /* bytes in response buffer */
    uint32_t            rTotal = 0;                /* total allocated bytes */
    int                 ctrlfd;
    int                 ctrlclntfd;
    int                 sockfd;
    int                 ready;
    struct iovec        iov[3];
    uint32_t            ack = htobe32(0);
    struct tpm2_resp_prefix respprefix;
    uint32_t            lastCommand;
    uint32_t            frame_used = 0;
    uint64_t            frame_generation = 0;
    unsigned char       *effective = NULL, *outgoing;
    const unsigned char *original_response;
    uint32_t            effective_length = 0, outgoing_length;
    bool                synthetic = false, backend_executed;
    const char          *response_source;
    bool                intercept_failed = false;
#ifdef WITH_LUA
    struct lua_transmit_context transmit_context = { mlp, &tpm_running };
#endif
    enum TPMLIB_TPMProperty prop = (mlp->tpmversion == TPMLIB_TPM_VERSION_1_2)
        ? TPMPROP_TPM_BUFFER_MAX
        : TPMPROP_TPM2_BUFFER_MAX;

    /* poolfd[] indexes */
    enum {
        DATA_CLIENT_FD = 0,
        NOTIFY_FD,
        CTRL_SERVER_FD,
        CTRL_CLIENT_FD,
        DATA_SERVER_FD
    };

    TPM_DEBUG("mainLoop:\n");

    max_command_length = tpmlib_get_tpm_property(prop) +
                         sizeof(struct tpm2_send_command_prefix);

    command = malloc(max_command_length);
    if (!command) {
        logprintf(STDERR_FILENO, "Could not allocate %u bytes for buffer.\n",
                  max_command_length);
        return TPM_FAIL;
    }

#ifdef WITH_LUA
    lua_intercept_set_transmit(mlp->lua, mainloop_lua_transmit, &transmit_context);
#endif

    /* header and trailer that we may send by setting iov_len */
    iov[0].iov_base = &respprefix;
    iov[0].iov_len = 0;
    iov[2].iov_base = &ack;
    iov[2].iov_len = 0;

    connection_fd.fd = -1;
    ctrlfd = ctrlchannel_get_fd(mlp->cc);
    ctrlclntfd = ctrlchannel_get_client_fd(mlp->cc);

    sockfd = SWTPM_IO_GetSocketFD();

    if (mlp->startupType != _TPM_ST_NONE) {
        command_length = tpmlib_create_startup_cmd(
                                  mlp->startupType,
                                  mlp->tpmversion,
                                  command, max_command_length);
        if (command_length > 0) {
            pcap_packet_record_write(&mlp->ps, command, command_length, true);
            (void)lua_intercept_internal(mlp->lua, command, command_length, true, 0);
            if (mlp->lua && (mlp->ps.failed || lua_intercept_failed(mlp->lua)))
                goto intercept_error;

            mlp->lastCommand = tpmlib_get_cmd_ordinal(command, command_length);
            rc = TPMLIB_Process(&rbuffer, &rlength, &rTotal,
                                command, command_length);

            if (!rc)
                pcap_packet_record_write(&mlp->ps, rbuffer, rlength, false);
            (void)lua_intercept_internal(mlp->lua, rc ? NULL : rbuffer,
                                    rc ? 0 : rlength, false, rc);
        }

        if (rc || command_length == 0) {
            g_mainloop_terminate = true;
            if (rc)
                logprintf(STDERR_FILENO, "Could not send Startup: 0x%x\n", rc);
        }
    }

    if (mlp->lua && (mlp->ps.failed || lua_intercept_failed(mlp->lua) || rc))
        goto intercept_error;

    while (!g_mainloop_terminate) {

        while (rc == 0) {
            if (mlp->flags & MAIN_LOOP_FLAG_USE_FD) {
                if (connection_fd.fd != mlp->fd) {
                    SWTPM_IO_Disconnect(&connection_fd);
                    connection_fd.fd = mlp->fd;
                    frame_used = 0;
                }
            }

            struct pollfd pollfds[] = {
                [DATA_CLIENT_FD] = {
                    .fd = connection_fd.fd,
                    .events = POLLIN | POLLHUP,
                    .revents = 0,
                },
                [NOTIFY_FD] = {
                    .fd = notify_fd,
                    .events = POLLIN,
                    .revents = 0,
                },
                [CTRL_SERVER_FD] = {
                    .fd = -1,
                    .events = POLLIN,
                    .revents = 0,
                },
                [CTRL_CLIENT_FD] = {
                    .fd = ctrlclntfd,
                    .events = POLLIN | POLLHUP,
                    .revents = 0,
                },
                [DATA_SERVER_FD] = {
                    /* listen socket for accepting clients */
                    .fd = -1,
                    .events = POLLIN,
                    .revents = 0,
                }
            };

            /* only listen for clients if we don't have one */
            if (connection_fd.fd < 0)
                pollfds[DATA_SERVER_FD].fd = sockfd;
            if (ctrlclntfd < 0)
                pollfds[CTRL_SERVER_FD].fd = ctrlfd;

            ready = poll(pollfds, 5, -1);
            if (ready < 0 && errno == EINTR)
                continue;

            if (ready < 0 ||
                (pollfds[NOTIFY_FD].revents & POLLIN) != 0) {
                if (mlp->lua && (frame_used || ready < 0))
                    goto intercept_error;
                SWTPM_IO_Disconnect(&connection_fd);
                if (mlp->flags & MAIN_LOOP_FLAG_USE_FD)
                    mlp->fd = -1;
                break;
            }

            if (!mlp->lua && (pollfds[DATA_CLIENT_FD].revents & (POLLHUP | POLLERR))) {
                logprintf(STDERR_FILENO, "Data client disconnected\n");
                mlp->fd = -1;
                /* chardev and unixio get this signal, not tcp */
                if (mlp->flags & MAIN_LOOP_FLAG_END_ON_HUP) {
                    /* only the chardev terminates here */
                    g_mainloop_terminate = true;
                    break;
                }
            }

            if (pollfds[DATA_SERVER_FD].revents & POLLIN)
                connection_fd.fd = accept(pollfds[DATA_SERVER_FD].fd, NULL, 0);

            if (pollfds[CTRL_SERVER_FD].revents & POLLIN)
                ctrlclntfd = accept(ctrlfd, NULL, 0);

            if (pollfds[CTRL_CLIENT_FD].revents & POLLIN) {
                ctrlclntfd = ctrlchannel_process_fd(ctrlclntfd,
                                                    &g_mainloop_terminate,
                                                    &g_locality, &tpm_running,
                                                    mlp);
                if (ctrlclntfd < 0 &&
                    mlp->flags & MAIN_LOOP_FLAG_CTRL_END_ON_HUP)
                    g_mainloop_terminate = true;

                if (g_mainloop_terminate)
                    break;

                if (mlp->lua && (mlp->ps.failed || lua_intercept_failed(mlp->lua)))
                    goto intercept_error;
                if (mlp->lua && frame_used &&
                    frame_generation != mlp->initialization_generation) {
                    /* Never splice a partial command across a TPM reset. */
                    lua_intercept_fail(mlp->lua, "TPM initialized during a partial request");
                    goto intercept_error;
                }
            }

            if (pollfds[CTRL_CLIENT_FD].revents & POLLHUP) {
                if (ctrlclntfd >= 0)
                    close(ctrlclntfd);
                ctrlclntfd = -1;
                /* unixio gets this signal, not tcp */
                if (mlp->flags & MAIN_LOOP_FLAG_CTRL_END_ON_HUP) {
                    g_mainloop_terminate = true;
                    break;
                }
            }

            if (!(pollfds[DATA_CLIENT_FD].revents &
                  (mlp->lua ? (POLLIN | POLLHUP | POLLERR | POLLNVAL) : POLLIN)))
                continue;

            /* Read the command.  The number of bytes is determined by 'paramSize' in the stream */
            if (mlp->lua) {
                uint32_t limit = mlp->buffer_size ? mlp->buffer_size :
                                  (uint32_t)tpmlib_get_tpm_property(prop);
                int framed;

                if (limit > max_command_length) {
                    unsigned char *larger = realloc(command, limit);
                    if (!larger)
                        goto intercept_error;
                    command = larger;
                    max_command_length = limit;
                }
                if (!frame_used)
                    frame_generation = mlp->initialization_generation;
                framed = SWTPM_IO_ReadRawTPM2(connection_fd.fd, command, &frame_used, limit);
                if (framed < 0) {
                    lua_intercept_framing_error(mlp->lua, command, frame_used);
                    goto intercept_error;
                }
                if (framed == 2) {
                    SWTPM_IO_Disconnect(&connection_fd);
                    if (mlp->flags & MAIN_LOOP_FLAG_USE_FD)
                        mlp->fd = -1;
                    if (mlp->flags & (MAIN_LOOP_FLAG_TERMINATE | MAIN_LOOP_FLAG_END_ON_HUP))
                        g_mainloop_terminate = true;
                    break;
                }
                if (framed == 0)
                    continue;
                command_length = frame_used;
                frame_used = 0;
                if (pcap_packet_record_write(&mlp->ps, command, command_length, true))
                    goto intercept_error;
                effective = command;
                effective_length = command_length;
                synthetic = false;
                if (lua_intercept_request(mlp->lua, command, command_length,
                                           g_locality, limit, &effective,
                                           &effective_length, &synthetic))
                    goto intercept_error;
            } else if (rc == 0) {
                rc = SWTPM_IO_Read(&connection_fd, command, &command_length,
                                   max_command_length, &mlp->ps);
                if (rc != 0) {
                    /* connection broke */
                    SWTPM_IO_Disconnect(&connection_fd);
                }
            }

            cmd_offset = 0;
            /* Handle optional TCG Header in front of TPM 2 Command */
            if (rc == 0 && !mlp->lua && mlp->tpmversion == TPMLIB_TPM_VERSION_2) {
                cmd_offset = tpmlib_handle_tcg_tpm2_cmd_header(command,
                                                               command_length,
                                                               &g_locality);
                if (cmd_offset > 0) {
                    /* send header and trailer */
                    iov[0].iov_len = sizeof(respprefix);
                    iov[2].iov_len = sizeof(ack);
                } else {
                    iov[0].iov_len = 0;
                    iov[2].iov_len = 0;
                }
            }

            if (!mlp->lua) {
                effective = &command[cmd_offset];
                effective_length = command_length - cmd_offset;
                synthetic = false;
            }
            backend_executed = false;
            response_source = synthetic ? "lua" : "swtpm";
            if (synthetic)
                goto skip_process;

            /* Synthetic replies need no backend or storage access. */
            if (rc == 0 && !mainloop_ensure_locked_storage(mlp)) {
                if (mlp->lua)
                    goto intercept_error;
                g_mainloop_terminate = true;
                break;
            }

            if (rc == 0) {
                if (!tpm_running) {
                    tpmlib_write_fatal_error_response(&rbuffer, &rlength,
                                                      &rTotal,
                                                      mlp->tpmversion);
                    goto skip_process;
                }
            }

            if (rc == 0) {
                rlength = 0;                                /* clear the response buffer */
                rc = tpmlib_process(&rbuffer,
                                    &rlength,
                                    &rTotal,
                                    effective,
                                    effective_length,
                                    mlp->locality_flags,
                                    &g_locality,
                                    mlp->tpmversion);
                if (rlength)
                    goto skip_process;
            }

            if (rc == 0) {
                if (lua_intercept_backend(mlp->lua, effective, effective_length, true))
                    goto intercept_error;
                lastCommand = tpmlib_get_cmd_ordinal(effective, effective_length);
                if (lastCommand != TPM_ORDINAL_NONE)
                    mlp->lastCommand = lastCommand;
                backend_executed = true;
                response_source = "tpm";
                rlength = 0;                                /* clear the response buffer */
                rc = TPMLIB_Process(&rbuffer,
                                    &rlength,
                                    &rTotal,
                                    effective,
                                    effective_length);
                lua_intercept_processed(mlp->lua, rc);
                if (rc == 0 && lua_intercept_backend(mlp->lua, rbuffer, rlength, false))
                    goto intercept_error;
            }

skip_process:
            if (mlp->lua && (rc || lua_intercept_failed(mlp->lua)))
                goto intercept_error;
            /* write the results */
            if (rc == 0) {
                outgoing_length = rlength;
                original_response = synthetic ?
                    lua_intercept_synthetic(mlp->lua, &outgoing_length) : rbuffer;
                if (mlp->lua && (!original_response || outgoing_length < 10))
                    goto intercept_error;
                outgoing = (unsigned char *)original_response;
                if (lua_intercept_response(mlp->lua, original_response, outgoing_length,
                                            backend_executed, response_source,
                                            &outgoing, &outgoing_length))
                    goto intercept_error;
                respprefix.size = htobe32(outgoing_length);
                iov[1].iov_base = outgoing;
                iov[1].iov_len  = outgoing_length;

                rc = SWTPM_IO_Write(&connection_fd, iov, ARRAY_LEN(iov), &mlp->ps);
                lua_intercept_complete(mlp->lua, rc);
                if (mlp->lua && (rc || mlp->ps.failed || lua_intercept_failed(mlp->lua)))
                    goto intercept_error;
            }

            if (!(mlp->flags & MAIN_LOOP_FLAG_KEEP_CONNECTION)) {
                SWTPM_IO_Disconnect(&connection_fd);
                break;
            }
        }

        rc = 0; /* A fatal TPM_Process() error should cause the TPM to enter shutdown.  IO errors
                   are outside the TPM, so the TPM does not shut down.  The main loop should
                   continue to function.*/
        if (connection_fd.fd < 0 && mlp->flags & MAIN_LOOP_FLAG_TERMINATE)
            break;
    }

    if (mlp->lua && frame_used)
        goto intercept_error;
    goto shutdown;

intercept_error:
    intercept_failed = true;
    lua_intercept_fail(mlp->lua, "transport, processing or capture failure");
    lua_intercept_complete(mlp->lua, rc ? rc : TPM_FAIL);

shutdown:
#ifdef WITH_LUA
    lua_intercept_set_transmit(mlp->lua, NULL, NULL);
#endif
    if (tpm_running && !mlp->disable_auto_shutdown)
        tpmlib_maybe_send_tpm2_shutdown(mlp->tpmversion, &mlp->lastCommand,
                                        &mlp->ps, mlp->lua);

    if (mlp->lua && (intercept_failed || mlp->ps.failed || lua_intercept_failed(mlp->lua)))
        rc = TPM_FAIL;

    free(rbuffer);
    free(command);

    if (ctrlclntfd >= 0)
        close(ctrlclntfd);
    ctrlchannel_set_client_fd(mlp->cc, -1);

    if (connection_fd.fd >= 0 && !(mlp->flags & MAIN_LOOP_FLAG_USE_FD))
        close(connection_fd.fd);

    if (mlp->fd >= 0) {
        close(mlp->fd);
        mlp->fd = -1;
    }

    return rc;
}
