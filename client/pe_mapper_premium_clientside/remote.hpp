#pragma once
#include <string>
#include <cstdint>
#include <Windows.h>
#include <TlHelp32.h>

#include "str_transformer.hpp"


namespace remote {
	inline std::uintptr_t get_module_base(::HANDLE proc, const std::string& module_name) noexcept {
		auto snaphsot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(proc));

		if (!snaphsot || snaphsot == INVALID_HANDLE_VALUE) {
			return 0;
		}

		::MODULEENTRY32W entry = { .dwSize = sizeof(entry) };
		if (!Module32FirstW(snaphsot, &entry)) {
			CloseHandle(snaphsot);
			return 0;
		}

		auto w_s_module = ::str_transformer::str_to_wstr(module_name);
		::str_transformer::stolower(w_s_module);

		do {
			auto module_name = std::wstring(entry.szModule);
			::str_transformer::stolower(module_name);
			::str_transformer::truncate(module_name);

			if (!wcscmp(module_name.c_str(), w_s_module.c_str())) {
				CloseHandle(snaphsot);
				return reinterpret_cast<uintptr_t>(entry.modBaseAddr);
			}
		} while (Module32Next(snaphsot, &entry));

		CloseHandle(snaphsot);
		return 0;
	}

	inline bool write_raw(::HANDLE proc, std::uint64_t addr, const void* buffer, std::size_t size, std::size_t* size_written) noexcept {
		return
			WriteProcessMemory(proc,
				reinterpret_cast<LPVOID>(addr),
				buffer,
				size,
				(SIZE_T*)size_written);
	}

	inline bool read_raw(::HANDLE proc, std::uint64_t addr, void* buffer, std::size_t size, std::size_t* size_read) noexcept {
		return
			ReadProcessMemory(
				proc,
				reinterpret_cast<LPVOID>(addr),
				buffer,
				size,
				(SIZE_T*)size_read);
	}

	inline std::uintptr_t alloc_raw(::HANDLE proc, std::size_t size, std::uint32_t protect = PAGE_EXECUTE_READWRITE, std::uint32_t type = MEM_COMMIT) noexcept {
		return reinterpret_cast<uintptr_t>(VirtualAllocEx(proc,
			0,
			size,
			type,
			protect));
	}

	inline bool free_raw(::HANDLE proc, std::uint64_t addr) noexcept {
		return
			VirtualFreeEx(
				proc,
				reinterpret_cast<::LPVOID>(addr),
				0,
				MEM_RELEASE);
	}

	inline std::uintptr_t get_proc_address(::HANDLE proc, std::uintptr_t mod_base, const std::string& func_name) {
		static std::uintptr_t region = 0;
		static std::uintptr_t p_mod_base = 0;
		static std::uintptr_t p_func_name = 0;
		static std::uintptr_t p_result = 0;

		if (!region) {
			std::vector<std::uint8_t> shellcode = {
				0x68, 0x88, 0x14, 0x88, 0x14, // push 0x14881488
				0xFF, 0x35, 0x37, 0x13, 0x37, 0x13, //  push dword ptr [0x13371337]
				0xB8, 0x37, 0x13, 0x37, 0x13, // mov eax, 0x1337
				0xFF, 0xD0, // call eax
				0xA3, 0x37, 0x13, 0x37, 0x13, // mov dword ptr [0x1337], eax 
				0xC3, // ret
			};

			region = alloc_raw(proc, 0x1000, PAGE_EXECUTE_READWRITE, MEM_COMMIT);
			p_mod_base = region + shellcode.size();
			p_result = p_mod_base + sizeof(std::uintptr_t);
			p_func_name = p_result + sizeof(std::uintptr_t);

			*reinterpret_cast<std::uintptr_t*>(&shellcode[1]) = p_func_name;
			*reinterpret_cast<std::uintptr_t*>(&shellcode[7]) = p_mod_base;
			*reinterpret_cast<std::uintptr_t*>(&shellcode[12]) = reinterpret_cast<uintptr_t>(GetProcAddress);
			*reinterpret_cast<std::uintptr_t*>(&shellcode[19]) = p_result;
			
			if (!write_raw(proc, region, shellcode.data(), shellcode.size(), nullptr))
				throw std::runtime_error("unable to write shellcode");
		}

		std::uintptr_t result = 0;
		if (!write_raw(proc, p_result, &result, sizeof(result), nullptr))
			throw std::runtime_error("unable to reset shellcode");

		if (!write_raw(proc, p_mod_base, &mod_base, sizeof(mod_base), nullptr))
			throw std::runtime_error("unable to write shellcode [0]");

		std::vector<std::uint8_t> func_name_raw(func_name.length() + 1);
		std::memcpy(func_name_raw.data(), func_name.data(), func_name.length());
		func_name_raw[func_name.length()] = '\0';

		if (!write_raw(proc, p_func_name, func_name_raw.data(), func_name_raw.size(), nullptr))
			throw std::runtime_error("unable to write shellcode [1]");

		WaitForSingleObject(CreateRemoteThread(proc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(region), nullptr, 0, nullptr), -1);

		if (!read_raw(proc, p_result, &result, sizeof(result), nullptr))
			throw std::runtime_error("unable to read result [2]");

		return result;
	}
}
