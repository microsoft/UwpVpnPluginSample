#pragma once
#include "Utils.h"

using namespace winrt::Windows::Networking::Vpn;
using namespace winrt::Windows::Networking::Sockets;

using namespace winrt::Windows::Foundation::Collections;
using namespace winrt::Windows::Security::Cryptography::Certificates;

using namespace winrt::Windows::Data::Xml;
using namespace winrt::Windows::Data::Xml::Dom;


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

enum class VPN_PLUGIN_TRANSPORT_TYPE
{
	VPN_PLUGIN_TRANSPORT_TYPE_TCP,
	VPN_PLUGIN_TRANSPORT_TYPE_UDP,
	VPN_PLUGIN_TRANSPORT_TYPE_DUAL,
	VPN_PLUGIN_TRANSPORT_TYPE_MAX
};

class CustomConfiguration
{
	
	public:
	bool IsV2;
	VpnTrafficFilterAssignment trafficFilterAssignment;
	std::vector<VPN_AUTHENTICATION> authentications;
	std::vector<IVector<IVpnCustomPrompt>> preAuthCustomPrompts;
	std::vector<IVector<IVpnCustomPrompt>> postAuthCustomPrompts;

	VPN_PLUGIN_TRANSPORT_TYPE transportType = VPN_PLUGIN_TRANSPORT_TYPE::VPN_PLUGIN_TRANSPORT_TYPE_TCP;
	bool connectedTcp;
	bool connectedUdp;

	std::wstring clientIpV4;
	std::wstring clientIpV6;
	std::wstring clientIpReconnectV4;
	std::wstring clientIpReconnectV6;
	std::wstring portServiceName;

	SocketProtectionLevel protectionLevel = SocketProtectionLevel::PlainSocket;
	VpnRouteAssignment routeAssignment;
	IVector<VpnRoute> ipv4InclusionRoutes{ winrt::single_threaded_vector<VpnRoute>() };
	IVector<VpnRoute> ipv4ExclusionRoutes{ winrt::single_threaded_vector<VpnRoute>() };
	IVector<VpnRoute> ipv6InclusionRoutes{ winrt::single_threaded_vector<VpnRoute>() };
	IVector<VpnRoute> ipv6ExclusionRoutes{ winrt::single_threaded_vector<VpnRoute>() };
	bool excludeLocalSubnets;

	VpnNamespaceAssignment namespaceAssignment;
	IVector<VpnNamespaceInfo> namespaceList{ winrt::single_threaded_vector<VpnNamespaceInfo>() };

	//v2 Addition
	VpnDomainNameAssignment domainnameAssignment;
	std::vector<VpnDomainNameInfo> domainnameList;

	// <summary>
	// Default frame size to use. This is only used if no other frame size is specified via custom
	// configuration XML.
	// </summary>
	std::uint32_t maxFrameSize = 1501;

	// <summary>
	// Default port to use when connecting to the VPN server. This is only used if no other port was
	// specified via custom configuration XML.
	// </summary>
	std::wstring defaultPort = L"443";

	// <summary>
	// This member is used to keep track of whether we are being asked to connect for the first time
	// or whether we are reconnecting. Depending on the plug-in configuration, we may want to do
	// different things during reconnect, so after the first connection we will set this to true
	// </summary>
	bool IsReconnect;

	bool packetCapture;

	bool bufferCapture;
	
	void ParseConfiguration(const WCHAR* configXml, bool isReconnect, VpnChannel const& channel);

	bool ConvertXmlToCustomPrompt(IXmlNode promptXml, IVector<IVpnCustomPrompt>& customPrompt);
	bool ConvertXmlToRoute(IXmlNode routeXml, VpnRoute& route);
	int GenerateRandomInt(int min, int max);
};

