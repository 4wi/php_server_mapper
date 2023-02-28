#pragma once
#include <Windows.h>
#include <string>
#include <algorithm>


namespace str_transformer {
	inline void stolower(std::string& data) noexcept {
		std::transform(data.begin(), data.end(), data.begin(), tolower);
	}

	inline void stolower(std::wstring& data) noexcept {
		std::transform(data.begin(), data.end(), data.begin(), towlower);
	}

	inline void stolower(std::wstring& data, std::size_t size) noexcept {
		std::transform(data.begin(), data.begin() + size, data.begin(), towlower);
	}

	inline void truncate(std::string& data) noexcept {
		data.erase(std::find(data.begin(), data.end(), '\0'), data.end());
	}

	inline void truncate(std::wstring& data) noexcept {
		data.erase(std::find(data.begin(), data.end(), '\0'), data.end());
	}

	inline std::string wstr_to_str(const std::wstring& data) noexcept {

		if (data.empty()) {
			return {};
		}

		const int str_len =
			WideCharToMultiByte(
				CP_UTF8,
				0,
				data.data(), static_cast<int>(data.size()),
				nullptr, 0, nullptr, nullptr
			);

		std::string out;
		out.resize(str_len);

		WideCharToMultiByte(
			CP_UTF8,
			0,
			data.data(), static_cast<int>(data.size()),
			&out[0], str_len,
			nullptr, nullptr
		);

		return out;
	}

	inline std::string wstr_to_str(const std::wstring_view data) noexcept {

		if (data.empty()) {
			return {};
		}

		const int str_len =
			WideCharToMultiByte(
				CP_UTF8,
				0,
				data.data(), static_cast<int>(data.size()),
				nullptr, 0, nullptr, nullptr
			);

		std::string out;
		out.resize(str_len);

		WideCharToMultiByte(
			CP_UTF8,
			0,
			data.data(), static_cast<int>(data.size()),
			&out[0], str_len,
			nullptr, nullptr
		);

		return out;
	}

	inline std::wstring str_to_wstr(const std::string& data) noexcept {
		if (data.empty()) {
			return {};
		}

		const int str_len =
			MultiByteToWideChar(
				CP_UTF8,
				0,
				data.data(), static_cast<int>(data.size()),
				nullptr, 0
			);

		std::wstring out;
		out.resize(str_len);

		MultiByteToWideChar(
			CP_UTF8,
			0,
			data.data(), static_cast<int>(data.size()),
			&out[0], str_len
		);

		return out;
	}

	inline std::wstring str_to_wstr(const std::string_view data) noexcept {
		if (data.empty()) {
			return {};
		}

		const int str_len =
			MultiByteToWideChar(
				CP_UTF8,
				0,
				data.data(), static_cast<int>(data.size()),
				nullptr, 0
			);

		std::wstring out;
		out.resize(str_len);

		MultiByteToWideChar(
			CP_UTF8,
			0,
			data.data(), static_cast<int>(data.size()),
			&out[0], str_len
		);

		return out;
	}
}