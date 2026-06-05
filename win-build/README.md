# git-crypt — Windows (MSVC) build

Everything required to build a **self-contained x64 Windows `git-crypt.exe`**
lives in this folder, kept separate from the upstream tree so syncing upstream
never conflicts with our changes.

The produced exe:

- is **x64**,
- **statically links the MSVC CRT** (`/MT`) — no VC++ Redistributable needed,
- uses a **Windows-native crypto backend (CNG / BCrypt)** — no OpenSSL needed,
- depends only on `bcrypt.dll` + `KERNEL32.dll` (both are Windows system DLLs).

---

## Build

From a normal terminal (the script loads the VS environment itself):

```cmd
win-build\build.cmd                 :: Release (default)
win-build\build.cmd debug           :: Debug
win-build\build.cmd clean           :: wipe build\ then Release
win-build\build.cmd debug clean
```

Or directly with PowerShell:

```powershell
win-build\build.ps1 -Mode Release
win-build\build.ps1 -Mode Debug -Clean
```

Output: **`win-build\dist\git-crypt.exe`**.

After building, `build.ps1` runs `dumpbin /dependents` and **fails the build**
if the exe ever picks up a `vcruntime`/`msvcp`/`api-ms-win-crt`/OpenSSL
dependency — so the "no runtime required" guarantee is enforced, not assumed.

### Requirements

- Visual Studio 2022/2026 with the **"Desktop development with C++"** workload
  (provides MSVC, plus the bundled CMake and Ninja).
- That's it — no OpenSSL, no vcpkg, no perl.

Compiler discovery (vswhere → `Enter-VsDevShell`) mirrors
`D:\github\discrete\build.ps1`.

---

## How it works

`build.ps1` loads the VS x64 developer environment, then configures and builds
[`CMakeLists.txt`](CMakeLists.txt) with Ninja. That CMake project:

- compiles the **upstream sources from the parent directory** (`..`),
- **excludes** `crypto-openssl-11.cpp`,
- **adds** [`crypto-win32.cpp`](crypto-win32.cpp) in its place,
- sets `CMAKE_MSVC_RUNTIME_LIBRARY = MultiThreaded[Debug]` (static CRT),
- links `bcrypt`.

`util.cpp` and `coprocess.cpp` already `#include` their `*-win32.cpp` halves
under `#ifdef _WIN32`, so the Windows platform code is upstream's own.

### Crypto backend (`crypto-win32.cpp`)

A drop-in replacement for `crypto-openssl-11.cpp`, implementing the same three
primitives on the OS crypto API (CNG / `bcrypt.dll`):

| git-crypt primitive   | CNG implementation                                  |
|-----------------------|-----------------------------------------------------|
| `Aes_ecb_encryptor`   | AES-256, `BCRYPT_CHAIN_MODE_ECB`, single 16-byte block (CTR is built on top in upstream `crypto.cpp`) |
| `Hmac_sha1_state`     | `BCRYPT_SHA1_ALGORITHM` + `BCRYPT_ALG_HANDLE_HMAC_FLAG` |
| `random_bytes`        | `BCryptGenRandom(BCRYPT_USE_SYSTEM_PREFERRED_RNG)`  |

Because CNG ships in Windows, the binary needs no third-party crypto library.
The file lives here (not in the repo root) so it never collides with upstream.

---

## Required source modifications (in the upstream tree)

These are the **only** edits made to upstream files. They are portability fixes
that are also correct on Unix, so they should merge cleanly and could even be
contributed upstream:

1. **`git-crypt.cpp`** — guard `#include <unistd.h>` with `#ifndef _WIN32`
   (MSVC has no `<unistd.h>`).
2. **`commands.cpp`** — on `_WIN32`, include `<io.h>` and define `F_OK`
   instead of `<unistd.h>` (for `access()`).
3. **`crypto.hpp`** — give the `Aes_ctr_encryptor` enum a fixed
   `unsigned long long` underlying type. `MAX_CRYPT_BYTES` is 2³⁶; MSVC
   otherwise types the unscoped enum as `int` and **truncates it to 0**, which
   makes git-crypt reject every non-empty file ("file too long to encrypt
   securely"). GCC/Clang widen it automatically, so this is invisible on Unix.

Everything else (build system, crypto backend, scripts, docs) is additive and
lives under `win-build/`.

---

## Verified

The build is functionally tested (not just compiled): in a throwaway git repo,
`git-crypt init` → commit (file encrypted in git) → `lock` (working tree
encrypted) → `unlock` (plaintext restored byte-for-byte). This exercises the
full BCrypt AES-CTR + HMAC-SHA1 + RNG paths through git's own filter pipeline.

---

## Keeping in sync with upstream

The strategy is: **upstream files change as little as possible; our stuff is
isolated in `win-build/`.** To pull upstream updates:

```cmd
git fetch upstream
git merge upstream/master        :: or rebase — your choice
```

Conflicts, if any, will only be in the three files listed above, and the diffs
are tiny `#ifdef` guards. Re-run `win-build\build.cmd` afterwards.

> **Pushing to `origin` (your fork `bbfox0703/git-crypt`) is fine; never push to
> `upstream` (`AGWA/git-crypt`)** — upstream is a Unix project. See the repo-root
> `CLAUDE.md` for the full rule.
