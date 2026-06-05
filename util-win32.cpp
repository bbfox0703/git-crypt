/*
 * Copyright 2014 Andrew Ayer
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
 *
 * Additional permission under GNU GPL version 3 section 7:
 *
 * If you modify the Program, or any covered work, by linking or
 * combining it with the OpenSSL project's OpenSSL library (or a
 * modified version of that library), containing parts covered by the
 * terms of the OpenSSL or SSLeay licenses, the licensors of the Program
 * grant you additional permission to convey the resulting work.
 * Corresponding Source for a non-source form of such a combination
 * shall include the source code for the parts of OpenSSL used as well
 * as that of the covered work.
 */

#include <io.h>
#include <stdio.h>
#include <fcntl.h>
#include <windows.h>
#include <aclapi.h>
#include <vector>
#include <cstring>

namespace {
	// Builds a SECURITY_ATTRIBUTES / DACL granting the current user full control
	// and *nothing else* -- inheritance from the parent directory is blocked
	// (SE_DACL_PROTECTED). This is the Windows analogue of creating a file with
	// Unix mode 0600. We need it because a repo can live on a drive whose default
	// ACL grants BUILTIN\Users / Authenticated Users read access (common on
	// secondary data drives), which would otherwise leave key files and plaintext
	// temp files readable by every local user.
	class Owner_only_security {
		std::vector<char>	token_user;	// backing storage for TOKEN_USER (+ SID)
		PACL			dacl;		// allocated by SetEntriesInAcl -> LocalFree
		SECURITY_DESCRIPTOR	sd;
		SECURITY_ATTRIBUTES	sa;
		bool			ok;
	public:
		Owner_only_security () : dacl(nullptr), ok(false)
		{
			HANDLE	token = nullptr;
			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
				return;
			}
			DWORD	needed = 0;
			GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
			if (needed != 0) {
				token_user.resize(needed);
				if (!GetTokenInformation(token, TokenUser, &token_user[0], needed, &needed)) {
					token_user.clear();
				}
			}
			CloseHandle(token);
			if (token_user.empty()) {
				return;
			}
			PSID	user_sid = reinterpret_cast<TOKEN_USER*>(&token_user[0])->User.Sid;

			EXPLICIT_ACCESSA	ea;
			ZeroMemory(&ea, sizeof(ea));
			ea.grfAccessPermissions = GENERIC_ALL;
			ea.grfAccessMode        = SET_ACCESS;
			ea.grfInheritance       = NO_INHERITANCE;
			ea.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
			ea.Trustee.TrusteeType  = TRUSTEE_IS_USER;
			ea.Trustee.ptstrName    = reinterpret_cast<LPSTR>(user_sid);

			if (SetEntriesInAclA(1, &ea, nullptr, &dacl) != ERROR_SUCCESS) {
				dacl = nullptr;
				return;
			}
			// SE_DACL_PROTECTED is essential: without it the system *merges* the
			// parent directory's inheritable ACEs into our explicit DACL, and the
			// file stays readable by whoever the parent grants.
			if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION) ||
			    !SetSecurityDescriptorDacl(&sd, TRUE, dacl, FALSE) ||
			    !SetSecurityDescriptorControl(&sd, SE_DACL_PROTECTED, SE_DACL_PROTECTED)) {
				return;
			}
			sa.nLength              = sizeof(sa);
			sa.lpSecurityDescriptor = &sd;
			sa.bInheritHandle       = FALSE;
			ok = true;
		}
		~Owner_only_security ()
		{
			if (dacl) {
				LocalFree(dacl);
			}
		}
		bool			good () const  { return ok; }
		LPSECURITY_ATTRIBUTES	attributes ()  { return ok ? &sa : nullptr; }
		PACL			acl ()         { return ok ? dacl : nullptr; }

		Owner_only_security (const Owner_only_security&) = delete;
		Owner_only_security& operator= (const Owner_only_security&) = delete;
	};
}

std::string System_error::message () const
{
	std::string	mesg(action);
	if (!target.empty()) {
		mesg += ": ";
		mesg += target;
	}
	if (error) {
		LPTSTR	error_message;
		FormatMessageA(
			FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			nullptr,
			error,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			reinterpret_cast<LPTSTR>(&error_message),
			0,
			nullptr);
		mesg += error_message;
		LocalFree(error_message);
	}
	return mesg;
}

void	temp_fstream::open (std::ios_base::openmode mode)
{
	close();

	char			tmpdir[MAX_PATH + 1];

	DWORD			ret = GetTempPath(sizeof(tmpdir), tmpdir);
	if (ret == 0) {
		throw System_error("GetTempPath", "", GetLastError());
	} else if (ret > sizeof(tmpdir) - 1) {
		throw System_error("GetTempPath", "", ERROR_BUFFER_OVERFLOW);
	}

	char			tmpfilename[MAX_PATH + 1];
	if (GetTempFileName(tmpdir, TEXT("git-crypt"), 0, tmpfilename) == 0) {
		throw System_error("GetTempFileName", "", GetLastError());
	}

	filename = tmpfilename;

	// GetTempFileName just created an *empty* file. Before any plaintext spills
	// into it, lock it down to the current user only (Unix mkstemp() does the
	// same via umask 0077) and flag it temporary so Windows prefers to keep it
	// in cache rather than eagerly flush plaintext to physical disk. The ACL is
	// best-effort defence-in-depth; the file is still DeleteFile()d in close().
	{
		Owner_only_security	security;
		if (security.good()) {
			SetNamedSecurityInfoA(const_cast<LPSTR>(filename.c_str()), SE_FILE_OBJECT,
				DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
				nullptr, nullptr, security.acl(), nullptr);
		}
	}
	SetFileAttributesA(filename.c_str(), FILE_ATTRIBUTE_TEMPORARY);

	std::fstream::open(filename.c_str(), mode);
	if (!std::fstream::is_open()) {
		DeleteFile(filename.c_str());
		throw System_error("std::fstream::open", filename, 0);
	}
}

void	temp_fstream::close ()
{
	if (std::fstream::is_open()) {
		std::fstream::close();
		DeleteFile(filename.c_str());
	}
}

void	mkdir_parent (const std::string& path)
{
	std::string::size_type		slash(path.find('/', 1));
	while (slash != std::string::npos) {
		std::string		prefix(path.substr(0, slash));
		if (GetFileAttributes(prefix.c_str()) == INVALID_FILE_ATTRIBUTES) {
			// prefix does not exist, so try to create it
			if (!CreateDirectory(prefix.c_str(), nullptr)) {
				throw System_error("CreateDirectory", prefix, GetLastError());
			}
		}

		slash = path.find('/', slash + 1);
	}
}

std::string our_exe_path ()
{
	std::vector<char>	buffer(128);
	size_t			len;

	while ((len = GetModuleFileNameA(nullptr, &buffer[0], buffer.size())) == buffer.size()) {
		// buffer may have been truncated - grow and try again
		buffer.resize(buffer.size() * 2);
	}
	if (len == 0) {
		throw System_error("GetModuleFileNameA", "", GetLastError());
	}

	return std::string(buffer.begin(), buffer.begin() + len);
}

int exit_status (int status)
{
	return status;
}

void	touch_file (const std::string& filename)
{
	HANDLE	fh = CreateFileA(filename.c_str(), FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
	if (fh == INVALID_HANDLE_VALUE) {
		DWORD	error = GetLastError();
		if (error == ERROR_FILE_NOT_FOUND) {
			return;
		} else {
			throw System_error("CreateFileA", filename, error);
		}
	}
	SYSTEMTIME	system_time;
	GetSystemTime(&system_time);
	FILETIME	file_time;
	SystemTimeToFileTime(&system_time, &file_time);

	if (!SetFileTime(fh, nullptr, nullptr, &file_time)) {
		DWORD	error = GetLastError();
		CloseHandle(fh);
		throw System_error("SetFileTime", filename, error);
	}
	CloseHandle(fh);
}

void	remove_file (const std::string& filename)
{
	if (!DeleteFileA(filename.c_str())) {
		DWORD	error = GetLastError();
		if (error == ERROR_FILE_NOT_FOUND) {
			return;
		} else {
			throw System_error("DeleteFileA", filename, error);
		}
	}
}

static void	init_std_streams_platform ()
{
	_setmode(_fileno(stdin), _O_BINARY);
	_setmode(_fileno(stdout), _O_BINARY);
}

void create_protected_file (const char* path)
{
	// Create the (empty) file with an owner-only DACL *before* the caller writes
	// any secret into it, so the key material is never momentarily exposed under
	// the parent directory's (possibly world-readable) inherited permissions.
	// OPEN_ALWAYS mirrors Unix open(O_CREAT) semantics: the security descriptor
	// is applied only when the file is newly created; an existing file is left
	// untouched (and is truncated+rewritten by the caller's ofstream).
	Owner_only_security	security;
	if (!security.good()) {
		// Refuse to write a key file we cannot lock down -- failing loudly is
		// safer than silently creating one with inherited permissions.
		throw System_error("create_protected_file", path, GetLastError());
	}
	HANDLE	fh = CreateFileA(path, GENERIC_WRITE, 0, security.attributes(),
				OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (fh == INVALID_HANDLE_VALUE) {
		throw System_error("CreateFileA", path, GetLastError());
	}
	CloseHandle(fh);
}

int util_rename (const char* from, const char* to)
{
	// On Windows OS, it is necessary to ensure target file doesn't exist
	unlink(to);
	return rename(from, to);
}

std::vector<std::string> get_directory_contents (const char* path)
{
	std::vector<std::string>	filenames;
	std::string			patt(path);
	if (!patt.empty() && patt[patt.size() - 1] != '/' && patt[patt.size() - 1] != '\\') {
		patt.push_back('\\');
	}
	patt.push_back('*');

	WIN32_FIND_DATAA		ffd;
	HANDLE				h = FindFirstFileA(patt.c_str(), &ffd);
	if (h == INVALID_HANDLE_VALUE) {
		throw System_error("FindFirstFileA", patt, GetLastError());
	}
	do {
		if (std::strcmp(ffd.cFileName, ".") != 0 && std::strcmp(ffd.cFileName, "..") != 0) {
			filenames.push_back(ffd.cFileName);
		}
	} while (FindNextFileA(h, &ffd) != 0);

	DWORD				err = GetLastError();
	if (err != ERROR_NO_MORE_FILES) {
		throw System_error("FileNextFileA", patt, err);
	}
	FindClose(h);
	return filenames;
}
