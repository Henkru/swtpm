# Lua interception interface

Lua interception requires a build configured with `--with-lua` and
`swtpm socket --tpm2`. Load a Lua 5.4 script with `--lua-script PATH` or
`--lua-script-fd N`. The script must be a regular text file, at most 1 MiB;
an inherited file descriptor must be at least 3. Interception supports raw
TPM 2 messages, including QEMU's passed data FD, but not the optional TCG prefix.

## Script and interception flow

The script runs once before traffic is accepted and must return a table with
integer `api_version = 1` and at least one of these callbacks:

```lua
return {
    api_version = 1,
    on_request = function(ctx, request)
        ctx.state.request_digest = tpm.sha256(request)
        return { action = "pass" }
    end,
    on_response = function(ctx, response)
        assert(ctx.state.request_digest == tpm.sha256(ctx.original_request))
        return { action = "pass" }
    end,
}
```

Each external exchange follows this sequence:

1. swtpm reads and validates a complete request, then calls
   `on_request(ctx, request)` with the original request bytes.
2. The callback passes or replaces the request, or supplies a synthetic response.
   The *effective request* is the original or replacement request selected for
   processing. A synthetic response skips that processing entirely.
3. swtpm obtains an original response from the TPM, from swtpm-local handling
   (such as an error before TPM execution), or from the request callback's
   synthetic response. It calls `on_response(ctx, response)` once with those bytes.
4. The response callback passes or replaces the response. swtpm sends this
   *final response* to the client and releases its per-exchange state reference.

A missing callback passes its input unchanged. Callbacks return one of:

| Return value | In `on_request` | In `on_response` |
| --- | --- | --- |
| `nil`, no return, or `{ action = "pass" }` | Process the original request. | Deliver the original response. |
| `{ action = "replace", bytes = message }` | Process `message` instead. | Deliver `message` instead. |
| `{ action = "respond", bytes = message }` | Skip request processing and pass `message` to `on_response`. | Invalid. |

Messages are complete binary Lua strings, including their TPM headers.
Replacement and synthetic messages must be at least 10 bytes, fit the negotiated
buffer limit, and have a declared size equal to the string length. Accepted tags
are `0x8001` and `0x8002`; responses also allow tag `0x00c4` for an exactly
10-byte `TPM_RC_BAD_TAG` (`0x1e`) response. swtpm does not recompute authorization
HMACs or parameter encryption after modifications.

Errors abort the exchange, so later steps may not run. Invalid callback returns,
script errors, budget violations, and processing, capture, or delivery failures
stop swtpm with a nonzero status and retain partial artifacts. A normal TPM error
response still goes through `on_response`.

Automatic swtpm Startup/Shutdown commands bypass the callbacks. Commands sent by
the script through `tpm.transmit()` also bypass them, as described below.

## The `ctx` table

Both callbacks receive these fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | integer | External exchange ID, starting at 1 and increasing across the script's lifetime. Additional `tpm.transmit()` calls do not consume IDs. |
| `generation` | integer | swtpm TPM initialization generation captured when the exchange begins. Zero before initialization; increases on successful swtpm initialization, including control-channel reinitialization. This is not a count of TPM Startup commands. |
| `tpm_version` | integer | Always `2`. |
| `locality` | integer | Locality captured at the start of the exchange; inherited by additional commands. |
| `command_code` | integer | Command code from the original request, even when the request is replaced. |
| `original_request` | binary string | Complete request received from the client, before modification. |
| `transmit_limit` | integer | Maximum additional commands per callback invocation: `64`. |
| `state` | table | Mutable table shared between the request and response callbacks for this exchange. Starts empty for each exchange. |

The response callback additionally receives:

| Field | Type | Meaning |
| --- | --- | --- |
| `effective_request` | binary string or `nil` | Complete original or replacement request selected for processing. `nil` for synthetic responses. Its presence does not guarantee TPM execution. |
| `effective_command_code` | integer or `nil` | Code from `effective_request`; `nil` for synthetic responses. |
| `backend_executed` | boolean | Whether the effective external request was submitted to libtpms. Does not indicate TPM success or count additional commands. |
| `response_source` | string | `"tpm"` for a backend response, `"swtpm"` for a local response, or `"lua"` for a synthetic response. Describes the input to the response callback. |

Context metadata is copied into a fresh table for each callback. Assigning
`ctx.locality`, `ctx.transmit_limit`, or other metadata changes only that Lua
table. Use callback return values to change traffic.

Mutate `ctx.state` to carry data between callbacks, for example
`ctx.state.modified = true`. Assigning `ctx.state = {}` does not replace the
retained state table that the response callback will receive. Globals and
captured Lua variables persist until process exit, including across TPM
reinitializations; use `ctx.generation` when cached state depends on the TPM.

## Functions in `tpm`

Call these functions with dot syntax, such as `tpm.sha256(data)`. All byte
arguments and results are binary strings, not hex text; embedded zero bytes are
preserved and numbers are not coerced to strings. Invalid arguments and helper
failures raise fatal Lua errors. Crypto helpers run in memory using OpenSSL and
do not send TPM commands. They and `tpm.log` are available during script
initialization and callbacks; `tpm.transmit` requires an active callback.

### `response, rc = tpm.transmit(command)`

Synchronously execute exactly one complete raw TPM 2 command on the same TPM
instance and return its complete response plus the integer response code from
the TPM header. Supply exactly one string argument, with tag `0x8001` or `0x8002`,
matching declared length, and size within the negotiated buffer limit. The
response must also have valid framing and fit that limit.

Calls execute immediately in order, without entering either interceptor callback
or swtpm-local command handling such as SetLocality. In `on_request`, they finish
before the effective external request executes. In `on_response`, they finish
before the final external response is delivered. The limit is 64 calls in each
callback independently, including calls made through Lua helper functions.

Additional responses go only to Lua; explicitly return one in a `respond` or
`replace` action to deliver it to the client. Additional commands do not change
the enclosing exchange's context, including `backend_executed` and
`response_source`. They do change real TPM state: handles, sessions, and other
state changes persist even if the handler later fails or returns a synthetic
response. There is no rollback, automatic Startup, authentication repair, or retry.

A nonzero TPM `rc` is a normal return that the script can inspect. An unavailable
TPM, storage failure, libtpms processing failure, invalid response, or log failure
is fatal. Calling this function during script initialization is also an error.
See [the additional-command example](samples/lua/transmit.lua).

### `digest = tpm.sha256(data)`

Return the 32-byte SHA-256 digest of `data`. Input may be empty and is limited
to 1 MiB (1,048,576 bytes).

### `mac = tpm.hmac_sha256(key, data)`

Return the 32-byte HMAC-SHA-256 value. `key` is limited to 1 KiB (1,024 bytes)
and `data` to 1 MiB. Either may be empty.

### `plaintext = tpm.rsa_oaep_sha256_decrypt(private_der, ciphertext, label)`

Decrypt a 256-byte RSA-2048 ciphertext using OAEP with SHA-256 for both OAEP and
MGF1. `private_der` must contain one complete, unencrypted PKCS#8 RSA-2048 private
key with no trailing DER, be nonempty, and fit in 4 KiB (4,096 bytes). The modulus
must be positive, odd, and 2048 bits. The resulting plaintext must be exactly
32 bytes, as for a TPM session salt; other plaintext lengths are errors.

### `ciphertext = tpm.rsa_oaep_sha256_encrypt(modulus, exponent, plaintext, label)`

Encrypt an exactly 32-byte plaintext using RSA-2048 OAEP with SHA-256 for both
OAEP and MGF1, returning 256 bytes. `modulus` is exactly 256 bytes encoding an
unsigned, big-endian, odd, 2048-bit integer. `exponent` must be an odd Lua integer
from 3 through 4,294,967,295; translate a TPM-encoded exponent of zero to 65,537
before calling. Encryption uses OpenSSL randomness.

For both RSA functions, `label` is required, may be empty, and is limited to
64 bytes. It is used exactly as supplied, without adding or removing a
terminator: `"SECRET\0"` supplies seven bytes.

### `salt = tpm.ecc_p256_salt_from_private(private_der, ephemeral_point)`

Derive a 32-byte TPM ECC session salt from an attacker-controlled static
private key and a client's ephemeral public point. `private_der` must contain
one complete, unencrypted PKCS#8 EC private key with no trailing DER, be
nonempty, fit in 4 KiB, use the named `prime256v1`/NIST P-256 group, and contain
valid private and public components. `ephemeral_point` is exactly 68 bytes: a
32-byte unsigned big-endian X coordinate prefixed by `00 20`, followed by the
same encoding for Y. Coordinates must be canonical field elements defining a
non-infinity point on P-256.

The helper performs P-256 ECDH and TPM KDFe with SHA-256, counter 1, the exact
seven-byte label `"SECRET\0"`, the client ephemeral X coordinate as party U,
and the private key's static public X coordinate as party V. The hash's complete
32-byte output is returned.

### `ephemeral_point, salt = tpm.ecc_p256_salt_to_public(static_point)`

Generate a fresh P-256 ephemeral key using OpenSSL randomness, derive ECDH with
the supplied static public point, and return the generated public point plus
the 32-byte TPM KDFe salt. `static_point` and the returned point use the exact
68-byte encoding described above. KDFe uses the generated ephemeral X
coordinate as party U and the supplied static X coordinate as party V. A new
ephemeral key is generated for every call; keys and points cannot be supplied
in any other form and the label, hash, curve, ordering, and output length are
not configurable.

### `ciphertext = tpm.aes_128_cfb_encrypt(key, iv, plaintext)`

Encrypt using AES-128-CFB128 without padding. `key` and `iv` must each be
16 bytes. `plaintext` may be empty, is limited to 1 MiB, and need not be
block-aligned. The result has the same length as the plaintext.

### `plaintext = tpm.aes_128_cfb_decrypt(key, iv, ciphertext)`

Decrypt using AES-128-CFB128 without padding. `key` and `iv` must each be
16 bytes. `ciphertext` may be empty, is limited to 1 MiB, and need not be
block-aligned. The result has the same length as the ciphertext.

Crypto-helper inputs are immutable Lua strings and cannot be wiped by these
functions. Returned values are also Lua strings and are outside the C cleanup
guarantee. The helpers cleanse C-owned staging buffers for ECDH shared secrets,
derived salts, encoded ephemeral points, AES output, and partially produced
results on both success and failure; OpenSSL owns and releases its internal key
material. Errors use fixed non-secret text and do not include DER, points,
shared secrets, salts, keys, IVs, or payload bytes.

### `tpm.log(message)`

Write a binary string to the optional JSONL event log as exact hex bytes and
mirror a readable form to stderr; stderr output can stop at an embedded zero.
Returns no values. The cumulative limit is 4,096 bytes per initialization or
callback, charging each empty message one byte. Exceeding the limit or failing
to write the event log is fatal. Use this function for output; `print` is absent.

## Runtime and recording

Lua has a 16-MiB memory limit and a one-million-instruction budget per script
initialization or callback. Returned helper strings count toward the memory
limit. These budgets do not bound time spent inside TPM or OpenSSL calls.
Lua does not guarantee that released strings containing secrets are wiped.

Restricted base, string, table, and math libraries are available, including
`string.pack`, `string.unpack`, and native bitwise operators. `require` supports
preloaded modules and Lua files through `package.path`; relative paths use
swtpm's working directory. Modules are cached in `package.loaded` and are not
part of the main script snapshot or its hash. Native module loading, general
file/process I/O, coroutine and debug libraries, `load`, `loadfile`, `dofile`,
`pcall`, `xpcall`, metatable functions, `collectgarbage`, `print`, and `warn` are
unavailable.

| Option | Recorded traffic |
| --- | --- |
| `--lua-log-fd N` | JSONL script snapshot, limits, original/effective requests, original/final responses, processing and completion records, diagnostics, and additional commands. |
| `--lua-pcap-fd N` | Effective external requests actually sent to libtpms and their original responses. Excludes synthetic, swtpm-local, automatic, and additional-command exchanges. |
| `--pcap file=PATH` or `--pcap fd=N` | Original external requests and final responses, plus automatic swtpm commands. Excludes additional-command exchanges unless a response is explicitly returned to the client. |

Additional-command JSONL records have `origin="lua"`, `id=0`, the enclosing
exchange's `parent_id`, a `phase` of `on_request` or `on_response`, and a one-based
`sequence` shared across both handlers and reset per exchange. Their processing
`result` is the libtpms status; a valid response record's `result` is the TPM
response code. Their `backend_executed` describes that additional command.
Without `--lua-log-fd`, the additional exchanges are not captured.

See [samples/lua](samples/lua) for scripts and
[the swtpm manual](man/man8/swtpm.pod) for command-line and artifact FD details.
