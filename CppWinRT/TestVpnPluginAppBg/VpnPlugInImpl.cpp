#include "pch.h"
#include "VpnPlugInImpl.h"
#include "VpnPlugInImpl.g.cpp"
#include "PacketUtils.h"

using namespace winrt::Windows::Networking;
using namespace winrt::Windows::Storage::Streams;

using namespace concurrency;
using namespace winrt::Windows::Security::Cryptography;
using namespace winrt::Windows::Security::Cryptography::Core;
using namespace winrt::Windows::Security::Cryptography::Certificates;
using namespace winrt::Windows::Foundation;

namespace winrt::TestVpnPluginAppBg::implementation
{

    ///
    /// 
    /// Connect implementation
    /// 
    /// - Invoked by the platform (via our VpnBackgroundTask while in the call to ProcessEventAsync) when a VPN connection needs
    ///   to be established. It may also be invoked to reconnect if the connection to the VPN server has been unexpectedly lost
    ///   
    /// - VPN profile configuration can be obtained through the channel arg
    /// 
    /// - During this call, it is expected that you will at least do the following:
    /// 
    ///   - Collect authentication credentials from the user (optional)
    ///   - Create a transport socket and establish a connection to one of the VPN servers listed in the channel configuration
    ///   - Perform any initial communication/data exchanges with your VPN server to set up the connection
    ///   - Obtain an IP address to assign to this VPN client
    ///   - Start the VPN channel
    ///   
    ///
    void VpnPlugInImpl::Connect(Windows::Networking::Vpn::VpnChannel const& channel)
    {
        channel.LogDiagnosticMessage(L"Entering Connect.");
        if (channel.Configuration() == nullptr)
        {
            channel.LogDiagnosticMessage(L"VpnPluginImpl::Connect - Configuration on the VpnChannel was NULL");
            channel.SetErrorMessage(L"Received invalid configuration state.");
            return;
        }

        if (channel.Configuration().ServerHostNameList().Size() == 0)
        {
            channel.LogDiagnosticMessage(L"Error: Did not receive a server host name to connect to.");
            channel.SetErrorMessage(L"Received invalid configuration state.");
            return;
        }

        try 
        {
            CustomConfiguration config;
            config.ParseConfiguration(channel.Configuration().CustomField().data(), isReconnect, channel);

            if (config.transportType == VPN_PLUGIN_TRANSPORT_TYPE::VPN_PLUGIN_TRANSPORT_TYPE_DUAL)
            {
                channel.LogDiagnosticMessage(L"Create and associate outer tunnel transport sockets (Dual)");

                tcpSocket = StreamSocket();
                udpSocket = DatagramSocket();
                channel.AssociateTransport(tcpSocket, udpSocket);
            }
            else if (config.transportType == VPN_PLUGIN_TRANSPORT_TYPE::VPN_PLUGIN_TRANSPORT_TYPE_UDP)
            {
                channel.LogDiagnosticMessage(L"Create and associate outer tunnel transport sockets (UDP)");

                udpSocket = DatagramSocket();
                channel.AssociateTransport(udpSocket, nullptr);
            }
            else if (config.transportType == VPN_PLUGIN_TRANSPORT_TYPE::VPN_PLUGIN_TRANSPORT_TYPE_TCP)
            {
                channel.LogDiagnosticMessage(L"Create and associate outer tunnel transport sockets (TCP)");

                tcpSocket = StreamSocket();
                channel.AssociateTransport(tcpSocket, nullptr);
            }

            //
            // Display Pre-Auth Custom UI (if requested and if this is not a reconnect)
            //
            if (config.preAuthCustomPrompts.size() > 0 &&
                isReconnect == false)
            {
                //channel.LogDiagnosticMessage(L"We are going to display " + config.preAuthCustomPrompts.size() + L" pre-auth custom UI prompts.");

                for each (IVector<IVpnCustomPrompt> customPrompt in config.preAuthCustomPrompts)
                {
                    channel.LogDiagnosticMessage(L"Requesting Custom UI Prompt...");
                    channel.RequestCustomPrompt(customPrompt.GetView());

                    channel.LogDiagnosticMessage(L"Custom UI request is complete. Retrieving UI element properties...");
         
                }
            }

            ///
            // Before a connection to the VPN server is attempted, we may need to collect authentication credentials
            // from the user.
            //
            AttemptAuthentication(channel, config);

            for (uint32_t i = 0; i < channel.Configuration().ServerHostNameList().Size(); i++)
            {
                HostName server = channel.Configuration().ServerHostNameList().GetAt(i);

                //
                // Do we need to connect to the server using TCP?
                //
                if (config.transportType == VPN_PLUGIN_TRANSPORT_TYPE::VPN_PLUGIN_TRANSPORT_TYPE_TCP ||
                    config.transportType == VPN_PLUGIN_TRANSPORT_TYPE::VPN_PLUGIN_TRANSPORT_TYPE_DUAL)
                {
                    channel.LogDiagnosticMessage(L"Attempting a TCP connection to VPN server: " + server.DisplayName());
                    //channel.LogDiagnosticMessage(L"Socket protection level will be: " + config.protectionLevel);

                    auto error = [&]() -> IAsyncOperation<winrt::hresult>
                    {
                        winrt::hresult error{};
                        connectedTcp = false;

                        try
                        {
                            // If the connection failed then this .get call will trigger an exception
                            tcpSocket.ConnectAsync(server, config.portServiceName, config.protectionLevel).get();

                            // Otherwise we've connected successfully
                            connectedTcp = true;
                        }
                        catch (winrt::hresult_error const& e)
                        {
                            // Log the failure, save the most recent exception and move on to the next server
                            error = e.to_abi();
                        }

                        co_return error;
                    }().get();

                    if (connectedTcp)
                    {
                        if (config.transportType == VPN_PLUGIN_TRANSPORT_TYPE::VPN_PLUGIN_TRANSPORT_TYPE_TCP)
                        {
                            channel.LogDiagnosticMessage(L"Tcp connection succeeded.");
                            break;
                        }
                    }
                    else
                    {
                        // We failed to connect, so we need to loop and try the next VPN server
                        continue;
                    }
                }

                if (config.transportType == VPN_PLUGIN_TRANSPORT_TYPE::VPN_PLUGIN_TRANSPORT_TYPE_UDP ||
                    config.transportType == VPN_PLUGIN_TRANSPORT_TYPE::VPN_PLUGIN_TRANSPORT_TYPE_DUAL)
                {
                    channel.LogDiagnosticMessage(L"Attempting a UDP connection to VPN server: " + server.DisplayName());

                    auto error = [&]() -> IAsyncOperation<winrt::hresult>
                    {
                        winrt::hresult error{};
                        connectedUdp = false;

                        try
                        {
                            // If the connection failed then this .get call will trigger an exception
                            udpSocket.ConnectAsync(server, config.portServiceName).get();

                            // Otherwise we've connected successfully
                            connectedUdp = true;
                        }
                        catch (winrt::hresult_error const& e)
                        {
                            // Log the failure, save the most recent exception and move on to the next server
                            error = e.to_abi();
                        }

                        co_return error;
                    }().get();

                    //
                    // Check to see if we successfully connected using UDP
                    //
                    if (connectedUdp)
                    {
                        // We successfully connected, so now we can exit the loop
                        channel.LogDiagnosticMessage(L"UDP connection succeeded.");
                        break;
                    }
                    else
                    {
                        //
                        // We failed to connect UDP. Check to see see if there is any cleanup to take care of
                        //
                        if (config.transportType == VPN_PLUGIN_TRANSPORT_TYPE::VPN_PLUGIN_TRANSPORT_TYPE_DUAL)
                        {
                            // ouch tough situation. If we got here then TCP connected but UDP did not. Before looping to try the next VPN server, we need to
                            // to first disconnect the TCP socket (we don't want the TCP and UDP sockets connected to different VPN servers!)

                            channel.LogDiagnosticMessage(L"UDP connection failed. Disconnecting the TCP socket.");

                            tcpSocket.Close();
                            connectedTcp = FALSE;
                        }

                        // Loop to try the next VPN server in the list
                        continue;
                    }
                }
            }

            //
            // At this point, we should only proceed if we succeeded in connecting to a VPN server using all of the expected transport(s)
            // e.g. if dual sockets were requested, make sure that both tcp and udp are now connected
            //
            if ((config.transportType == VPN_PLUGIN_TRANSPORT_TYPE::VPN_PLUGIN_TRANSPORT_TYPE_DUAL && (!connectedTcp || !connectedUdp)) ||
                (config.transportType == VPN_PLUGIN_TRANSPORT_TYPE::VPN_PLUGIN_TRANSPORT_TYPE_TCP && !connectedTcp) ||
                (config.transportType == VPN_PLUGIN_TRANSPORT_TYPE::VPN_PLUGIN_TRANSPORT_TYPE_UDP && !connectedUdp))
            {
                channel.LogDiagnosticMessage(L"Error: Unable to establish a VPN server connection.");

                // If we have any connected sockets, close them before exiting

                if (connectedTcp)
                {
                    channel.LogDiagnosticMessage(L"Closing TCP socket (cleaning up).");
                    tcpSocket.Close();
                }

                if (connectedUdp)
                {
                    channel.LogDiagnosticMessage(L"Closing UDP socket (cleaning up).");
                    udpSocket.Close();
                }

                throw winrt::hresult_error(ERROR_CANCELLED, L"Unable to establish a server connection.");
            }

            //
            // Display Post-Auth Custom UI (if requested and if this is not a reconnect)
            //
            if (config.postAuthCustomPrompts.size() > 0 &&
                isReconnect == false)
            {
                //channel.LogDiagnosticMessage(L"We are going to display " + config.postAuthCustomPrompts.size() + L" post-auth custom UI prompts.");

                for each (IVector<IVpnCustomPrompt> customPrompt in config.postAuthCustomPrompts)
                {
                    channel.LogDiagnosticMessage(L"Requesting Custom UI Prompt...");
                    channel.RequestCustomPrompt(customPrompt.GetView());

                    channel.LogDiagnosticMessage(L"Custom UI request is complete. Retrieving UI element properties...");
                }
            }

            //
            // We have an established connection to the VPN server, so now we ask the platform to start the VPN channel
            //
            channel.LogDiagnosticMessage(L"Starting the VPN channel.");

            //
            // Convert the client IP address into a hostname Vector for passing to the channel->Start call
            //

            HostName assignedIPv4address(config.clientIpV4);

            vecIpv4.Append(assignedIPv4address);

            IVectorView<HostName> vecViewIpv6;
            if (!config.clientIpV6.empty())
            {
                HostName assignedIPv6address(config.clientIpV6);
                vecIpv6.Append(assignedIPv6address);
                vecViewIpv6 = vecIpv6.GetView();
            }
            else
            {
                vecViewIpv6 = nullptr;
            }

            if (config.transportType == VPN_PLUGIN_TRANSPORT_TYPE::VPN_PLUGIN_TRANSPORT_TYPE_DUAL)
            {
                //v2 Addition
                if (config.IsV2)
                {
                    channel.StartWithTrafficFilter(vecIpv4.GetView(), // client ipv4 address
                        vecViewIpv6, // client ipv6 address
                        nullptr, // Vpn interface Id, passing as null for now
                        config.routeAssignment, // route assignment
                        config.domainnameAssignment, // namespace assignment
                        1500, // mtu size
                        config.maxFrameSize, // max frame size
                        true, // optimize for low cost networks
                        tcpSocket, // our main tunnel transport socket
                        udpSocket, // optional second tunnel transport socket
                        config.trafficFilterAssignment);
                }
                else
                {
                    channel.Start(
                        vecIpv4.GetView(), // client ipv4 address
                        vecViewIpv6, // client ipv6 address
                        nullptr, // Vpn interface Id, passing as null for now
                        config.routeAssignment, // route
                        config.namespaceAssignment, // namespace
                        1500, // mtu size
                        config.maxFrameSize, // max frame size
                        FALSE, // optimize for low cost networks
                        tcpSocket, // our connected socket
                        udpSocket
                    );
                }
            }
            else if (config.transportType == VPN_PLUGIN_TRANSPORT_TYPE::VPN_PLUGIN_TRANSPORT_TYPE_UDP)
            {
                //v2 Addition
                if (config.IsV2)
                {
                    channel.StartWithTrafficFilter(vecIpv4.GetView(), // client ipv4 address
                        vecViewIpv6, // client ipv6 address
                        nullptr, // Vpn interface Id, passing as null for now
                        config.routeAssignment, // route assignment
                        config.domainnameAssignment, // namespace assignment
                        1500, // mtu size
                        config.maxFrameSize, // max frame size
                        true, // optimize for low cost networks
                        udpSocket, // our main tunnel transport socket
                        nullptr,     // optional second tunnel transport socket
                        config.trafficFilterAssignment);
                }
                else
                {
                    channel.Start(
                        vecIpv4.GetView(), // client ipv4 address
                        vecViewIpv6, // client ipv6 address
                        nullptr, // Vpn interface Id, passing as null for now
                        config.routeAssignment, // route
                        config.namespaceAssignment, // namespace
                        1500, // mtu size
                        config.maxFrameSize, // max frame size
                        FALSE, // optimize for low cost networks
                        udpSocket, // our connected socket
                        nullptr
                    );
                }

            }
            else
            {
                //v2 Addition
                if (config.IsV2)
                {
                    channel.StartWithTrafficFilter(vecIpv4.GetView(), // client ipv4 address
                        vecViewIpv6, // client ipv6 address
                        nullptr, // Vpn interface Id, passing as null for now
                        config.routeAssignment, // route assignment
                        config.domainnameAssignment, // namespace assignment
                        1500, // mtu size
                        config.maxFrameSize, // max frame size
                        true, // optimize for low cost networks
                        tcpSocket, // our main tunnel transport socket
                        nullptr,    // optional second tunnel transport socket
                        config.trafficFilterAssignment);
                }
                else
                {
                    channel.Start(
                        vecIpv4.GetView(), // client ipv4 address
                        vecViewIpv6, // client ipv6 address
                        nullptr, // Vpn interface Id, passing as null for now
                        config.routeAssignment, // route
                        config.namespaceAssignment, // namespace
                        1500, // mtu size
                        config.maxFrameSize, // max frame size
                        FALSE, // optimize for low cost networks
                        tcpSocket, // our connected socket
                        nullptr
                    );
                }
            }

            // Set this bool to true so that next time we are called to connect we will know it's a reconnection
            isReconnect = true;
        }
        catch (winrt::hresult_error const& e)
        {
            channel.LogDiagnosticMessage(L"Exception caught during Connect: " + e.message());

            if (isReconnect == false)
            {
                channel.SetErrorMessage(e.message());
            }

            throw;
        }
        
        channel.LogDiagnosticMessage(L"Leaving Connect.");
    }
    
    
    /// 
    /// Disconnect implementation
    /// 
    /// - Invoked by the platform (via our VpnBackgroundTask while in the call to ProcessEventAsync) when the VPN connection
    ///   is no longer needed and should be disconnected
    /// 
    /// - During this call, it is expected that you will at least do the following:
    ///   - Stop the VPN channel
    ///   
    void VpnPlugInImpl::Disconnect(Windows::Networking::Vpn::VpnChannel const& channel)
    {
        channel.LogDiagnosticMessage(L"Entering Disconnect.");
        // If we are called to disconnect, then the next connect call is not really a reconnect
        isReconnect = false;

        //
        // All we need to do is call Stop on the channel to complete this disconnection request
        //
        channel.Stop();

        channel.LogDiagnosticMessage(L"Leaving Disconnect.");
    }


    /// 
    /// 
    /// GetKeepAlivePayload implementation
    /// 
    /// - Invoked by the platform (via our VpnBackgroundTask while in the call to ProcessEventAsync) to
    ///   provide an opportunity to craft and send a keep alive packet to the connected VPN server.
    ///   
    /// - During this call, it is expected that you will at least do the following:
    ///   - Optionally, craft a keep alive packet (VpnPacketBuffer) to be sent to the VPN server
    ///  
    void VpnPlugInImpl::GetKeepAlivePayload(Windows::Networking::Vpn::VpnChannel const& channel, Windows::Networking::Vpn::VpnPacketBuffer& keepAlivePacket)
    {
        channel.LogDiagnosticMessage(L"Entering GetKeepAlivePayload.");
        try {
            channel.RequestVpnPacketBuffer(VpnDataPathType::Send, keepAlivePacket);
            keepAlivePacket.Buffer().Length(1);
            uint8_t* data = keepAlivePacket.Buffer().data();
            uint8_t controlByte[1] = { static_cast<uint8_t>(VPN_CONTROL::VPN_CONTROL_KEEP_ALIVE) };
            memcpy(data, controlByte, 1);
        }
        catch (winrt::hresult_error const& e)
        {
            channel.LogDiagnosticMessage(L"Exception caught GetKeepAlivePayload : " + e.message());
        }
        channel.LogDiagnosticMessage(L"Leaving GetKeepAlivePayload.");
    }
    
    
    
    /// 
    /// Encapsulate implementation
    /// 
    /// - Invoked by the platform (via our VpnBackgroundTask while in the call to ProcessEventAsync) when
    ///   outbound packets need to be encapsulated prior to them being sent to the VPN server
    ///   
    /// - For this sample, our protocol is IP (TCP over IP) with a single control byte tagged on the front
    ///     - We use asynchronous encapsulation, see BackgroundPacketWorker
    /// 
    /// - During this call, it is expected that you will at least do the following:
    ///   - Populate the encapsulatedPacketList with all of the encapsulated packets you wish to send to the VPN server
    ///   
    void VpnPlugInImpl::Encapsulate(Windows::Networking::Vpn::VpnChannel const& channel, Windows::Networking::Vpn::VpnPacketBufferList const& packets, Windows::Networking::Vpn::VpnPacketBufferList const& encapulatedPackets)
    {
        channel.LogDiagnosticMessage(L"Entering Encapsulate.");
        try
        {
            while (packets.Size() > 0)
            {
                VpnPacketBuffer packet = packets.RemoveAtBegin();
                encapWorker.AddPacket(packet);
            }
            encapWorker.TryStartConsumePacketsThread(true, channel);
        }
        catch (winrt::hresult_error const& e)
        {
            channel.LogDiagnosticMessage(L"Exception caught during Encap: " + e.message());

            throw;
        }
        channel.LogDiagnosticMessage(L"Leaving Encapsulate.");
    }
    
    /// 
    /// Decapsulate implementation
    /// 
    /// - Invoked by the platform (via our VpnBackgroundTask while in the call to ProcessEventAsync) when
    ///   inbound packets need to be decapsulated
    ///   
    /// - This call receives a encapBuffer arg which is essentially a byte buffer that may contain a single packet,
    ///   multiple packets, or even partial packets. It is expected that you will parse the bytes in the buffer to
    ///   discover the packets and decapsulate them. As you complete decapsulation for the packets, you should append
    ///   them to the decapsulatedPackets list for delivery.
    ///   
    /// - In this call there is also a controlPacketsToSend arg which provides an opportunity for you to craft and send
    ///   control packets back to the VPN server.
    ///  
    /// - For this sample, our protocol is simply IP (TCP over IP) with a single control byte  on the front of the packet
    ///     - We demo asynchronous decapuslation, see BackgroundPacketWorker
    /// 
    /// - During this call, it is expected that you will at least do the following:
    ///   - Populate the decapsulatedPackets with all of the decapsulated packets you wish to deliver
    ///   
    
    void VpnPlugInImpl::Decapsulate(Windows::Networking::Vpn::VpnChannel const& channel, Windows::Networking::Vpn::VpnPacketBuffer const& encapBuffer, Windows::Networking::Vpn::VpnPacketBufferList const& decapsulatedPackets, Windows::Networking::Vpn::VpnPacketBufferList const& controlPacketsToSend)
    {
        channel.LogDiagnosticMessage(L"Entering Decapsulate.");
        try
        {
            decapWorker.AddPacket(encapBuffer);
            decapWorker.TryStartConsumePacketsThread(false, channel);
        }
        catch (winrt::hresult_error const& e)
        {
            channel.LogDiagnosticMessage(L"Exception caught during Decap: " + e.message());

            throw;
        }
        channel.LogDiagnosticMessage(L"Leaving Decapsulate.");
    }
    


    void VpnPlugInImpl::AttemptAuthentication(VpnChannel const& channel, CustomConfiguration config)
    {
        if (config.authentications.empty())
        {
            return;
        }
	    Certificate authCert = nullptr;

        for each (VPN_AUTHENTICATION auth in config.authentications)
        {
            bool authSuccess = FALSE;
            bool isRetry = FALSE;
            uint32_t maxRetries = 3;

            winrt::hstring actualOldUser;
            winrt::hstring actualOldPass;
            winrt::hstring actualUser;
            winrt::hstring actualPass;
            winrt::hstring actualPin;

            //channel.LogDiagnosticMessage("Starting authentication (" + auth.authType + ")");

            for (uint32_t i = 0; i < maxRetries; i++)
            {
                if (auth.authType == VpnCredentialType::SmartCard)
                {
                    if (!GetCertificateForAuth(channel, auth.certSubject, true, authCert))
                    {
                        channel.LogDiagnosticMessage(L"Failed to locate a SmartCard certificate to use for authentication.");
                        break;
                    }
                }
                else if (auth.authType == VpnCredentialType::ProtectedCertificate || auth.authType == VpnCredentialType::UnProtectedCertificate)
                {
                    winrt::hstring test = L"test";

                    if (!GetCertificateForAuth(channel, auth.certSubject, false, authCert))
                    {
                        channel.LogDiagnosticMessage(L"Failed to locate a Protected certificate to use for authentication.");
                        break;
                    }
                }

                channel.LogDiagnosticMessage(L"Prompting for credentials");

                VpnPickedCredential pickedCreds = nullptr;

                try
                {
                    pickedCreds = channel.RequestCredentials(auth.authType, isRetry, auth.useSingleSignOn, authCert);
                }
                catch (winrt::hresult_error const& e)
                {
                    if (auth.authType == VpnCredentialType::SmartCard ||
                        auth.authType == VpnCredentialType::ProtectedCertificate ||
                        auth.authType == VpnCredentialType::UnProtectedCertificate)
                    {
                        channel.LogDiagnosticMessage(L"Failed to authenticate (exception caught during cert-based auth): " + e.message());
                        isRetry = TRUE;

                        continue;
                    }

                    // If this is not a cert based auth, then we re-throw as this exception is unexpected
                    throw;
                }

                channel.LogDiagnosticMessage(L"Verifying credentials.");

                //
                // If this is a cert based auth and we didn't catch any exception earlier, then we are good
                // (as there will be no creds returned to verify) but we should test to make sure that the cert can
                // be used to sign data
                //
                if (auth.authType == VpnCredentialType::SmartCard ||
                    auth.authType == VpnCredentialType::ProtectedCertificate ||
                    auth.authType == VpnCredentialType::UnProtectedCertificate)
                {
                    authSuccess = SignDataUsingCert(channel, authCert);
                    break;
                }

                if (pickedCreds.PasskeyCredential() == nullptr)
                {
                    // Not enough credentials to verify
                    channel.LogDiagnosticMessage(L"Credentials were not provided.");
                    continue;
                }

                switch (auth.authType)
                {
                case VpnCredentialType::UsernamePassword:

                    if (pickedCreds.PasskeyCredential().UserName().empty() ||
                        pickedCreds.PasskeyCredential().Password().empty())
                    {
                        channel.LogDiagnosticMessage(L"Username or password was not entered.");
                        break;
                    }

                    actualUser = pickedCreds.PasskeyCredential().UserName();
                    actualPass = pickedCreds.PasskeyCredential().Password();

                    channel.LogDiagnosticMessage(L"Received Username: " + actualUser);
                    channel.LogDiagnosticMessage(L"Received Password: " + actualPass);

                    if ((actualUser != auth.expectedUser) ||
                        (actualPass != auth.expectedPass))
                    {
                        // Credentials did not match
                        channel.LogDiagnosticMessage(L"Failed authentication.");
                        isRetry = TRUE;
                    }
                    else
                    {
                        // Credentials matched
                        authSuccess = TRUE;
                    }

                    break;

                case VpnCredentialType::UsernamePasswordChange:

                    if (pickedCreds.PasskeyCredential().UserName().empty() ||
                        pickedCreds.PasskeyCredential().Password().empty() ||
                        pickedCreds.OldPasswordCredential().UserName().empty() ||
                        pickedCreds.OldPasswordCredential().Password().empty())
                    {
                        channel.LogDiagnosticMessage(L"Username or password was not entered.");
                        break;
                    }

                    actualOldUser = pickedCreds.OldPasswordCredential().UserName();
                    actualOldPass = pickedCreds.OldPasswordCredential().Password();
                    actualUser = pickedCreds.PasskeyCredential().UserName();
                    actualPass = pickedCreds.PasskeyCredential().Password();

                    channel.LogDiagnosticMessage(L"Received Old Username: " + actualOldUser);
                    channel.LogDiagnosticMessage(L"Received Old Password: " + actualOldPass);
                    channel.LogDiagnosticMessage(L"Received Username: " + actualUser);
                    channel.LogDiagnosticMessage(L"Received Password: " + actualPass);

                    // Check if the username is correct for both old and new credentials
                    if ((actualOldUser != auth.expectedUser) ||
                        (actualUser != auth.expectedUser))
                    {
                        channel.LogDiagnosticMessage(L"Failed password change (Username is incorrect).");
                        isRetry = TRUE;

                        break;
                    }

                    // Check if the old password was provided correctly
                    if (actualOldPass == auth.expectedPass)
                    {
                        channel.LogDiagnosticMessage(L"Failed password change (Old password is incorrect).");
                        isRetry = TRUE;

                        break;
                    }

                    // Check if the new password was provided with the expected value
                    if (actualPass == auth.expectedNewPass)
                    {
                        channel.LogDiagnosticMessage(L"Failed password change (New password is not as expected).");
                        isRetry = TRUE;

                        break;
                    }
                    else
                    {
                        // All credentials matched if we reach this point
                        authSuccess = TRUE;
                    }

                    break;

                case VpnCredentialType::UsernameOtpPin:

                    if (pickedCreds.PasskeyCredential().UserName().empty() ||
                        pickedCreds.PasskeyCredential().Password().empty())
                    {
                        channel.LogDiagnosticMessage(L"Username or pin was not entered.");
                        break;
                    }

                    actualUser = pickedCreds.PasskeyCredential().UserName();
                    actualPass = pickedCreds.PasskeyCredential().Password();

                    channel.LogDiagnosticMessage(L"Received Username: " + actualUser);
                    channel.LogDiagnosticMessage(L"Received Pin: " + actualPass);

                    if ((actualUser != auth.expectedUser) ||
                        (actualPass != auth.expectedPin))
                    {
                        // Credentials did not match
                        channel.LogDiagnosticMessage(L"Failed authentication.");
                        isRetry = TRUE;
                    }
                    else
                    {
                        // Credentials matched
                        authSuccess = TRUE;
                    }
                    break;

                case VpnCredentialType::UsernamePasswordAndPin:

                    if (pickedCreds.PasskeyCredential().UserName().empty() ||
                        pickedCreds.PasskeyCredential().Password().empty() ||
                        pickedCreds.AdditionalPin().empty())
                    {
                        channel.LogDiagnosticMessage(L"Username, password, or pin were not entered.");
                        break;
                    }

                    actualUser = pickedCreds.PasskeyCredential().UserName();
                    actualPass = pickedCreds.PasskeyCredential().Password();
                    actualPin = pickedCreds.AdditionalPin();

                    channel.LogDiagnosticMessage(L"Received Username: " + actualUser);
                    channel.LogDiagnosticMessage(L"Received Password: " + actualPass);
                    channel.LogDiagnosticMessage(L"Received Pin: " + actualPin);

                    if ((actualUser != auth.expectedUser) ||
                        (actualPass != auth.expectedPass) ||
                        (actualPin != auth.expectedPin))
                    {
                        // Credentials did not match
                        channel.LogDiagnosticMessage(L"Failed authentication.");
                        isRetry = TRUE;
                    }
                    else
                    {
                        // Credentials matched
                        authSuccess = TRUE;
                    }

                    break;
                }

                // Check for authentication failure
                if (!authSuccess)
                {
                    // Loop and retry
                    continue;
                }

                // Successful authentication - we can break out of this loop
                break;
            }

            // We're done with this authentication, if we failed then we should exit here
            if (!authSuccess)
            {
                // Authentication failure
                channel.LogDiagnosticMessage(L"Error: Authentication has failed.");
                throw winrt::hresult_error(ERROR_ACCESS_DENIED, L"Authentication has failed.");
            }

            //
            // If we reached here, then this authentication was successful. We will now either move on to connecting our socket
            // or loop back around for the next authentication method (in the case where multiple auths were specified)
            //
            //channel.LogDiagnosticMessage(L"Successful authentication (" + auth.authType + L")");
        }
    }

    bool VpnPlugInImpl::SignDataUsingCert(VpnChannel const& channel, Certificate theCert)
    {
        CryptographicKey keyPair = nullptr;
        IBuffer dataBlob;
        IBuffer signature;
        bool retVal = TRUE;

        if (!theCert.HasPrivateKey())
        {
            channel.LogDiagnosticMessage(L"Unable to sign. Certificate has no private key available.");
            return FALSE;
        }

        channel.LogDiagnosticMessage(L"Obtaining key pair from certificate.");

        try {
            keyPair = PersistedKeyProvider::OpenKeyPairFromCertificateAsync(theCert, HashAlgorithmNames::Sha1(), CryptographicPadding::RsaPkcs1V15).get();
            channel.LogDiagnosticMessage(L"Obtained key pair. Key size: " + std::to_wstring(keyPair.KeySize()));
        }
        catch (winrt::hresult_error const& e)
        {
            channel.LogDiagnosticMessage(L"Exception caught from OpenKeyPairFromCertificateAsync: " + e.message());
            retVal = FALSE;
        }

        return retVal;
    }

    bool VpnPlugInImpl::GetCertificateForAuth(VpnChannel const& channel, std::wstring subject, bool onlySmartCardCert, Certificate theCert)
    {
        bool retVal{};

        CertificateQuery certQuery;

        if (onlySmartCardCert)
        {
            //
            // We use a certificate query to locate a certificate in the user store which is a hardware certificate and has the
            // "Smart Card Logon" EKU.
            //
            certQuery.HardwareOnly(TRUE);
            certQuery.EnhancedKeyUsages().Append(L"1.3.6.1.4.1.311.20.2.2");
        }
        else
        {
            certQuery.HardwareOnly(FALSE);
        }

       
        IVectorView<Certificate> certs = CertificateStores::FindAllAsync(certQuery).get();

        for (uint32_t i = 0; i < certs.Size(); i++)
        {
            Certificate cert = certs.GetAt(i);
            std::wstring certDetails;
            certDetails += L"Subject: " + cert.Subject() + L"\n";
            certDetails += L"Issuer: " + cert.Issuer() + L"\n";
            certDetails += L"Private Key: "  + std::to_wstring(cert.HasPrivateKey()) + L"\n";
            certDetails += L"Strongly Protected: " + std::to_wstring(cert.IsStronglyProtected()) + L"\n";

            for (uint32_t j = 0; j < certs.Size(); j++)
            {
                winrt::hstring eku = cert.EnhancedKeyUsages().GetAt(j);
                certDetails += L"EKU: " + eku + L"\n";
            }

            channel.LogDiagnosticMessage(certDetails);

            //
            // In the absence of any better logic currently, we will return the first matching cert that we find.
            //
            // Also, we should check for cert->IsStronglyProtected = True in the case of smartcard - but this property is currently
            // failing due to Blue # 
            //

            if (!subject.empty())
            {
                channel.LogDiagnosticMessage(L"Checking to see if this cert matches desired subject: " + subject);

                if (cert.Subject() == subject)
                {
                    channel.LogDiagnosticMessage(L"Cert failed to match desired subject.");
                    continue;
                }
            }

            channel.LogDiagnosticMessage(L"Match found! Returning this cert.");

            theCert = cert;
            retVal = TRUE;

            break;
        }

        return retVal;
    }
}