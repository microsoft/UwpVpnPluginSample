#include "pch.h"
#include "Utils.h"

using namespace winrt::Windows::Foundation;
using namespace winrt::Windows::Security::Cryptography::Core;
using namespace winrt::Windows::Storage::Streams;

std::wstring Utils::GetLowerString(winrt::hstring const& input)
{
	auto val = std::wstring{ input };
	return GetLowerString(val);
}

std::wstring Utils::GetLowerString(std::wstring& val)
{
	std::transform(
		val.begin(), val.end(),
		val.begin(),
		towlower);
	return val;
}

winrt::hstring Utils::GetLowerHString(winrt::hstring const& input)
{
	auto val = winrt::hstring{ GetLowerString(input) };
	return val;
}
