# git-crypt — Windows (MSVC) build

Everything required to build a **self-contained x64 Windows `git-crypt.exe`**
lives in this folder, kept separate from the upstream tree so syncing upstream
never conflicts with our changes.

The produced exe:

- is **x64**,
- **statically links the MSVC CRT** (`/MT`) — no VC++ Redistributable needed,
- uses a **Windows-native crypto backend (CNG / BCrypt)** — no OpenSSL needed,
- depends only on `bcrypt.dll`, `advapi32.dll` + `KERNEL32.dll` (all Windows
  system DLLs; `advapi32` is used for the process-token / ACL calls that lock
  key and temp files down to the current user — see [Security hardening](#security-hardening-windows)).

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

These are the edits made to upstream files. Items 1–3 are portability fixes that
are also correct on Unix (they should merge cleanly and could be contributed
upstream); item 4 is Windows-only security hardening:

1. **`git-crypt.cpp`** — guard `#include <unistd.h>` with `#ifndef _WIN32`
   (MSVC has no `<unistd.h>`).
2. **`commands.cpp`** — on `_WIN32`, include `<io.h>` and define `F_OK`
   instead of `<unistd.h>` (for `access()`).
3. **`crypto.hpp`** — give the `Aes_ctr_encryptor` enum a fixed
   `unsigned long long` underlying type. `MAX_CRYPT_BYTES` is 2³⁶; MSVC
   otherwise types the unscoped enum as `int` and **truncates it to 0**, which
   makes git-crypt reject every non-empty file ("file too long to encrypt
   securely"). GCC/Clang widen it automatically, so this is invisible on Unix.
4. **`util-win32.cpp`** — Windows security hardening (owner-only DACL for key
   and temp files; HMAC key-buffer wipe). This is Windows-only code, so any
   future upstream conflict is confined to `create_protected_file()` and
   `temp_fstream::open()`. Details in [Security hardening](#security-hardening-windows).
   (Upstream's Windows `create_protected_file()` is an empty stub, so upstream's
   own MinGW build shares the key-permissions weakness this fixes.)

Everything else (build system, crypto backend, scripts, docs) is additive and
lives under `win-build/`.

---

## Security hardening (Windows)

The Windows-native paths (BCrypt backend in `crypto-win32.cpp`, plus the platform
helpers in upstream `util-win32.cpp`) were hardened so the Windows build matches
the security properties of the Unix build:

- **Key files are created owner-only.** `create_protected_file()` (used by
  `git-crypt init`, `export-key`, `add-gpg-user`, …) now creates the key file
  with an explicit DACL granting **only the current user** and blocking inherited
  ACEs (`SE_DACL_PROTECTED`) — the Windows analogue of Unix `0600`. Previously it
  was an empty `// TODO`, so the key inherited the parent directory's ACL. On
  many drives (e.g. a secondary `D:`) that grants `BUILTIN\Users:(R)` /
  `Authenticated Users:(M)`, which left the repo's **master key readable by every
  local user**. Verified with `icacls`: the resulting key file shows only
  `<user>:(F)` and no inherited entries.
- **Plaintext temp files are locked down.** When a file larger than ~8 MB is
  encrypted, the overflow spills to a temp file in `%TEMP%`. It is now created
  owner-only (same DACL, via `SetNamedSecurityInfo`) and flagged
  `FILE_ATTRIBUTE_TEMPORARY`, and is deleted on close.
  *Residual:* `std::fstream` cannot share `FILE_FLAG_DELETE_ON_CLOSE`, so an
  abnormal termination (crash/kill) can still strand the temp file — unlike Unix,
  which `unlink()`s it immediately after open. The leftover is owner-only and
  temporary-attributed (so other users cannot read it), but it is not auto-removed
  on crash. Closing this gap fully would require replacing `temp_fstream`'s
  `std::fstream` base with a native `HANDLE`.
- **HMAC key material is wiped.** `Hmac_sha1_state`'s destructor now
  `explicit_memset`s the CNG hash-object buffer (which holds the HMAC key),
  matching the AES key-object wipe already present in the same file.

These add a link-time dependency on `advapi32.dll` (process-token + ACL APIs),
a core Windows system DLL — the self-contained / no-redistributable guarantee is
unchanged.

## Verified

The build is functionally tested (not just compiled): in a throwaway git repo,
`git-crypt init` → commit (file encrypted in git) → `lock` (working tree
encrypted) → `unlock` (plaintext restored byte-for-byte). This exercises the
full BCrypt AES-CTR + HMAC-SHA1 + RNG paths through git's own filter pipeline.

---

## Releases (CI)

[`.github/workflows/release-windows-msvc.yml`](../.github/workflows/release-windows-msvc.yml)
builds this exe on GitHub's `windows-latest` runner (VS + cmake + ninja are
preinstalled — no extra setup, since we need no OpenSSL) and publishes it to a
GitHub Release.

- **Trigger:** push a `v*` tag, e.g.:
  ```cmd
  git tag v0.8.0-win1
  git push origin v0.8.0-win1
  ```
  The workflow builds, computes a SHA256, and creates a Release with
  `git-crypt.exe` + `git-crypt.exe.sha256` attached.
- **Manual run** (`workflow_dispatch`, from the Actions tab) builds and uploads
  the artifact but does **not** create a release.
- The workflow file must live in `.github/workflows/` (GitHub requirement) — the
  only piece of our config that can't sit under `win-build/`. It has a distinct
  name and tag trigger, so it never collides with upstream's `release-windows.yml`
  (MSYS2/MinGW).
- Creating a release emits a `release: published` event. If you've enabled the
  upstream `release-*` workflows on the fork, they'll also fire — disable them in
  the fork's **Actions** tab (UI toggle, no file edit, merge stays clean).

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
