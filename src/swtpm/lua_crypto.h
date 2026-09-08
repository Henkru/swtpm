/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef SWTPM_LUA_CRYPTO_H
#define SWTPM_LUA_CRYPTO_H

#include <lua.h>

/* Add the fixed crypto helpers to the table at the top of the Lua stack. */
void lua_crypto_register(lua_State *L);

#endif /* SWTPM_LUA_CRYPTO_H */
