#pragma once
#include "VpnPlugInImpl.g.h"
#include "CustomConfiguration.h"
#include "Utils.h"
#include "BackgroundPacketWorker.h"

using namespace winrt::Windows::Networking;
using namespace winrt::Windows::Networking::Vpn;
using namespace winrt::Windows::Networking::Sockets;
using namespace winrt::Windows::Security::Cryptography::Core;

namespace winrt::TestVpnPluginAppBg::implementation
{
    struct VpnPlugInImpl : VpnPlugInImplT<VpnPlugInImpl>
    {
        VpnPlugInImpl() = default;
        bool isReconnect;
        StreamSocket tcpSocket{ nullptr };
        DatagramSocket udpSocket{ nullptr };

        bool connectedTcp;
        bool connectedUdp;
        IVector<HostName> vecIpv4{ winrt::single_threaded_vector<HostName>() };
        IVector<HostName> vecIpv6{ winrt::single_threaded_vector<HostName>() };

        BackgroundPacketWorker encapWorker;
        BackgroundPacketWorker decapWorker;

        void Connect(Windows::Networking::Vpn::VpnChannel const& channel);
        void Disconnect(Windows::Networking::Vpn::VpnChannel const& channel);
        void GetKeepAlivePayload(Windows::Networking::Vpn::VpnChannel const& channel, Windows::Networking::Vpn::VpnPacketBuffer& keepAlivePacket);
        void Encapsulate(Windows::Networking::Vpn::VpnChannel const& channel, Windows::Networking::Vpn::VpnPacketBufferList const& packets, Windows::Networking::Vpn::VpnPacketBufferList const& encapulatedPackets);
        void Decapsulate(Windows::Networking::Vpn::VpnChannel const& channel, Windows::Networking::Vpn::VpnPacketBuffer const& encapBuffer, Windows::Networking::Vpn::VpnPacketBufferList const& decapsulatedPackets, Windows::Networking::Vpn::VpnPacketBufferList const& controlPacketsToSend);

        void AttemptAuthentication(VpnChannel const& channel, CustomConfiguration config);
        bool GetCertificateForAuth(VpnChannel const& channel, std::wstring subject, bool onlySmartCardCert, Certificate theCert);
        bool SignDataUsingCert(VpnChannel const& channel, Certificate theCert);
    };
}
namespace winrt::TestVpnPluginAppBg::factory_implementation
{
    struct VpnPlugInImpl : VpnPlugInImplT<VpnPlugInImpl, implementation::VpnPlugInImpl>
    {
    };
}