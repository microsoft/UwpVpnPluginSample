#pragma once
#include <PacketUtils.h>

using namespace std;
using namespace winrt::Windows::Networking;
using namespace winrt::Windows::Networking::Vpn;
using namespace winrt::Windows::Networking::Sockets;

using namespace winrt::Windows::Storage::Streams;


struct VPN_PLUGIN_DECAP_STATE
{
	uint8_t* currentPartialPacket;
	uint16_t packetHostOrderTotalLength;
	uint32_t currentSize;
	bool isV6;
};

static void FinishWithCurrentPacket(winrt::Windows::Networking::Vpn::VpnChannel const& channel, VPN_PLUGIN_DECAP_STATE& state, uint8_t* buffer);

static void ProcessPacketVersion(uint8_t* buffer, uint32_t length, VPN_PLUGIN_DECAP_STATE& state);
static bool IsV6Packet(uint8_t* buffer);

static  VPN_CONTROL GetAndHandleControlByte(uint8_t* buffer);


class BackgroundPacketWorker
{
public:
	std::queue<VpnPacketBuffer> q;
	std::shared_mutex m;
	bool isWorking;
	VPN_PLUGIN_DECAP_STATE gDecapState;

	void AddPacket(VpnPacketBuffer buff);
	void EncapPacketLambda(winrt::Windows::Networking::Vpn::VpnChannel const& channel);
	void TryStartConsumePacketsThread(bool encap, winrt::Windows::Networking::Vpn::VpnChannel const& channel);
};

