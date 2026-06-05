# CLAUDE.md

Windows (MSVC) port of git-crypt. Keep this file minimal — details live in
linked docs.

## Core rules

1. **Push to `origin` (your fork `bbfox0703/git-crypt`) is fine. Never push to
   `upstream` (`AGWA/git-crypt`).** Upstream is a Unix project — only fetch/merge
   it *in*, never push our Windows changes out to it.
2. **Keep our changes isolated in [`win-build/`](win-build/).** Edit upstream
   source files only when unavoidable; minimal `#ifdef` guards so upstream
   merges stay clean. Current upstream edits are listed in
   [win-build/README.md](win-build/README.md#required-source-modifications-in-the-upstream-tree).
3. **Build target:** x64, static CRT (`/MT`), no MSVC runtime, no OpenSSL —
   crypto uses the Windows-native BCrypt backend.

## Build

```cmd
win-build\build.cmd            :: -> win-build\dist\git-crypt.exe
```

Needs Visual Studio with the C++ Desktop workload. Nothing else.

## More

- Full build/architecture/crypto/upstream-sync docs:
  [win-build/README.md](win-build/README.md)
- Upstream (Unix) build: the original `Makefile` and `INSTALL.md` are unchanged.

## Syncing upstream

```cmd
git fetch upstream && git merge upstream/master
```

Then rebuild with `win-build\build.cmd`. Expect conflicts only in the few
guarded upstream files (see win-build/README.md).
