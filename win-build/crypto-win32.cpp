/*
 * Copyright 2012, 2014 Andrew Ayer
 * Windows CNG (BCrypt) backend added 2026.
 *
 * This file is part of git-crypt.
 *
 * git-crypt is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * git-crypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with git-crypt.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * crypto-win32.cpp -- Windows-native crypto backend for git-crypt.
 *
 * This is a drop-in replacement for crypto-openssl-11.cpp. It implements the
 * exact same primitives the rest of git-crypt relies on:
 *
 *   - Aes_ecb_encryptor : single 16-byte block AES-256 encrypt (CTR is built
 *                         on top of this in the shared crypto.cpp)
 *   - Hmac_sha1_state   : keyed HMAC-SHA1
 *   - random_bytes      : cryptographically secure RNG
 *
 * It is built on the OS-provided Cryptography API: Next Generation (CNG),
 * a.k.a. bcrypt.dll. bcrypt.dll is a core Windows system component present on
 * every supported Windows version, so a git-crypt.exe using this backend needs
 * neither OpenSSL nor any redistributable runtime -- exactly the goal of the
 * static, self-contained Windows build. This file is NOT part of upstream and
 * lives under win-build/ so upstream merges stay conflict-free.
 */

#include "crypto.hpp"
#include "key.hpp"
#include "util.hpp"
#include <sstream>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace {
	// Throw a Crypto_error carrying the failing BCrypt call site + NTSTATUS.
	void check_nt (NTSTATUS status, const char* where)
	{
		if (!NT_SUCCESS(status)) {
			std::ostringstream	message;
			message << "BCrypt error 0x" << std::hex << static_cast<unsigned long>(status);
			throw Crypto_error(where, message.str());
		}
	}

	// Query BCRYPT_OBJECT_LENGTH so we can supply the key/hash object buffer
	// ourselves. Allocating it explicitly (rather than passing NULL) keeps the
	// behaviour identical across every supported Windows version.
	DWORD object_length (BCRYPT_ALG_HANDLE alg, const char* where)
	{
		DWORD	length = 0;
		DWORD	written = 0;
		check_nt(BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH,
					reinterpret_cast<PUCHAR>(&length), sizeof(length),
					&written, 0), where);
		return length;
	}
}

void init_crypto ()
{
	// CNG requires no global initialization (unlike OpenSSL's
	// ERR_load_crypto_strings()). Nothing to do.
}

// ===========================================================================
// AES-256 ECB (single block) via CNG
// ===========================================================================

struct Aes_ecb_encryptor::Aes_impl {
	BCRYPT_ALG_HANDLE		alg;
	BCRYPT_KEY_HANDLE		key;
	std::vector<unsigned char>	key_object;

	Aes_impl () : alg(nullptr), key(nullptr) { }
};

Aes_ecb_encryptor::Aes_ecb_encryptor (const unsigned char* raw_key)
: impl(new Aes_impl)
{
	check_nt(BCryptOpenAlgorithmProvider(&impl->alg, BCRYPT_AES_ALGORITHM, nullptr, 0),
			"Aes_ecb_encryptor::Aes_ecb_encryptor (open AES provider)");

	// ECB so each block is encrypted independently with no IV -- matches
	// OpenSSL's AES_encrypt(), which the CTR layer in crypto.cpp expects.
	check_nt(BCryptSetProperty(impl->alg, BCRYPT_CHAINING_MODE,
				reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_ECB)),
				sizeof(BCRYPT_CHAIN_MODE_ECB), 0),
			"Aes_ecb_encryptor::Aes_ecb_encryptor (set ECB mode)");

	impl->key_object.resize(object_length(impl->alg,
			"Aes_ecb_encryptor::Aes_ecb_encryptor (get object length)"));

	check_nt(BCryptGenerateSymmetricKey(impl->alg, &impl->key,
				impl->key_object.empty() ? nullptr : &impl->key_object[0],
				static_cast<ULONG>(impl->key_object.size()),
				const_cast<PUCHAR>(raw_key), KEY_LEN, 0),
			"Aes_ecb_encryptor::Aes_ecb_encryptor (generate key)");
}

Aes_ecb_encryptor::~Aes_ecb_encryptor ()
{
	// Note: explicit destructor necessary because the class holds a unique_ptr
	// to an incomplete type at its point of declaration.
	if (impl->key) {
		BCryptDestroyKey(impl->key);
	}
	if (impl->alg) {
		BCryptCloseAlgorithmProvider(impl->alg, 0);
	}
	// Wipe the residual key object material (the raw key bytes are owned by the
	// caller and wiped there).
	if (!impl->key_object.empty()) {
		explicit_memset(&impl->key_object[0], '\0', impl->key_object.size());
	}
}

void Aes_ecb_encryptor::encrypt (const unsigned char* plain, unsigned char* cipher)
{
	ULONG	out_len = 0;
	check_nt(BCryptEncrypt(impl->key,
				const_cast<PUCHAR>(plain), BLOCK_LEN,
				nullptr,		// no padding info (ECB)
				nullptr, 0,		// no IV (ECB)
				cipher, BLOCK_LEN,
				&out_len, 0),
			"Aes_ecb_encryptor::encrypt");
}

// ===========================================================================
// HMAC-SHA1 via CNG
// ===========================================================================

struct Hmac_sha1_state::Hmac_impl {
	BCRYPT_ALG_HANDLE		alg;
	BCRYPT_HASH_HANDLE		hash;
	std::vector<unsigned char>	hash_object;

	Hmac_impl () : alg(nullptr), hash(nullptr) { }
};

Hmac_sha1_state::Hmac_sha1_state (const unsigned char* key, size_t key_len)
: impl(new Hmac_impl)
{
	check_nt(BCryptOpenAlgorithmProvider(&impl->alg, BCRYPT_SHA1_ALGORITHM,
				nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG),
			"Hmac_sha1_state::Hmac_sha1_state (open HMAC-SHA1 provider)");

	impl->hash_object.resize(object_length(impl->alg,
			"Hmac_sha1_state::Hmac_sha1_state (get object length)"));

	check_nt(BCryptCreateHash(impl->alg, &impl->hash,
				impl->hash_object.empty() ? nullptr : &impl->hash_object[0],
				static_cast<ULONG>(impl->hash_object.size()),
				const_cast<PUCHAR>(key), static_cast<ULONG>(key_len), 0),
			"Hmac_sha1_state::Hmac_sha1_state (create hash)");
}

Hmac_sha1_state::~Hmac_sha1_state ()
{
	if (impl->hash) {
		BCryptDestroyHash(impl->hash);
	}
	if (impl->alg) {
		BCryptCloseAlgorithmProvider(impl->alg, 0);
	}
	// Wipe the residual HMAC key material left in the hash object buffer.
	// BCryptDestroyHash is not documented to zero the caller-supplied buffer,
	// so do it ourselves -- mirrors the key_object wipe in the AES path above.
	if (!impl->hash_object.empty()) {
		explicit_memset(&impl->hash_object[0], '\0', impl->hash_object.size());
	}
}

void Hmac_sha1_state::add (const unsigned char* buffer, size_t buffer_len)
{
	check_nt(BCryptHashData(impl->hash,
				const_cast<PUCHAR>(buffer), static_cast<ULONG>(buffer_len), 0),
			"Hmac_sha1_state::add");
}

void Hmac_sha1_state::get (unsigned char* digest)
{
	check_nt(BCryptFinishHash(impl->hash, digest, LEN, 0),
			"Hmac_sha1_state::get");
}

// ===========================================================================
// CSPRNG via CNG
// ===========================================================================

void random_bytes (unsigned char* buffer, size_t len)
{
	check_nt(BCryptGenRandom(nullptr, buffer, static_cast<ULONG>(len),
				BCRYPT_USE_SYSTEM_PREFERRED_RNG),
			"random_bytes");
}
