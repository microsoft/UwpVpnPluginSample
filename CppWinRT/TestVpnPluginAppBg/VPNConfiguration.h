#pragma once
#include "pch.h"

using namespace winrt::Windows::Networking::Vpn;

struct VPN_AUTHENTICATION
{
	VpnCredentialType authType;
	std::wstring expectedUser;
	std::wstring expectedPass;
	std::wstring expectedPin;
	std::wstring expectedNewPass;
	std::wstring certSubject;
	bool useSingleSignOn;
};

enum class VPN_PLUGIN_TYPE
{
	VPN_PLUGIN_TRANSPORT_TYPE_TCP,
	VPN_PLUGIN_TRANSPORT_TYPE_UDP,
	VPN_PLUGIN_TRANSPORT_TYPE_DUAL,
	VPN_PLUGIN_TRANSPORT_TYPE_MAX
};


class VpnConfiguration
{
};

