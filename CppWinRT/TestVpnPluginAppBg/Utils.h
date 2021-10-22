#pragma once

using namespace winrt::Windows::Storage::Streams;
class Utils
{
public:
	static std::wstring GetLowerString(winrt::hstring const& input);
	static std::wstring GetLowerString(std::wstring& val);
	static winrt::hstring GetLowerHString(winrt::hstring const& input);
};

