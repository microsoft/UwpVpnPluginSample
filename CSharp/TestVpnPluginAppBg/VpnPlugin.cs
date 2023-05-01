//
// This code provides our IVpnPlugin implementation (TestVpnPlugin) and some additional
// helper functions which are used by the plug-in during packet processing (e.g. decapsulating)
//

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading.Tasks;
using Windows.Networking;
using Windows.Networking.Vpn;
using Windows.Networking.Sockets;
using Windows.Storage.Streams;
using Windows.Security.Cryptography.Certificates;
using Windows.Security.Cryptography.Core;
using Windows.Security.Cryptography;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using Windows.ApplicationModel;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using System.IO;
using Windows.Foundation.Collections;

namespace TestVpnPluginAppBg
{
    /// <summary>
    /// Test VPN client Plug-in implementation
    /// </summary>
    public sealed class TestVpnPlugin : IVpnPlugIn
    {
        #region Consts

        //
        // Used by Decapsulate: It represents the length of packet data we must have in order to be able to understand a packets full length 
        // (i.e. to be able to access the TotalLength field of a IPV4_HEADER)
        //
        internal const UInt32 VALID_LENGTH = 4 + 1;
        internal const UInt32 VALID_LENGTH_V6 = 6 + 1;
        internal const ushort IPV6_HEADER_LENGTH = 40;
        internal const UInt32 PARTIAL_PACKET_SIZE = 64 * 1024 + 1;
        internal const string mappedMemoryName = "PacketCounter";

        #endregion

        #region Structs

        /// <summary>
        /// Used by Decapsulate: Structure used to store partial packets as they are being processed during decapsulation
        /// </summary>
        internal struct VPN_PLUGIN_DECAP_STATE
        {
            internal byte[] currentPartialPacket;
            internal ushort packetHostOrderTotalLength;
            internal uint currentSize;
            internal bool isV6;
        }
        #endregion

       

        #region Members

        /// <summary>
        /// TCP Socket used to connect to the VPN server
        /// </summary>
        StreamSocket tcpSocket;

        /// <summary>
        /// UDP socket used to connect to the VPN server
        /// </summary>
        DatagramSocket udpSocket;

        /// <summary>
        /// This important member is used to maintain state across multiple invocations of Decapsulate.
        /// It will be used to store any partial packets which we need to continue building on the next
        /// Decapsulate call
        /// </summary>
        internal VPN_PLUGIN_DECAP_STATE gDecapState;

        /// <summary>
        /// This member is used to keep track of whether we are being asked to connect for the first time
        /// or whether we are reconnecting. Depending on the plug-in configuration, we may want to do
        /// different things during reconnect, so after the first connection we will set this to true
        /// </summary>
        internal bool IsReconnect = false;

        /// <summary>
        /// This member is used to keep track of whether or not the neccessary APIs exist
        /// Used to demo how to check the existence of APIs when in older version of windows when API updates are made
        /// </summary>
        internal bool ApisExist = false;

        /// <summary>
        /// This is used to control how much logging the plug-in will do. It determines whether we log packets and
        /// and buffer values, as well as determining the how detailed we want out logs to be with log_level
        /// </summary>
        internal Logger logger = Logger.Instance;

        /// <summary>
        /// Contains several boolean values that determine whether we're in exception mode and where to throw exceptions
        /// for the purpose of testing
        /// </summary>
        internal EXCEPTION_MODE_FLAGS exceptionFlags = new EXCEPTION_MODE_FLAGS();

        ConcurrentQueue<VpnPacketBuffer> encapQueue = new ConcurrentQueue<VpnPacketBuffer>();
        BackgroundWorker encapWorker;

        ConcurrentQueue<byte[]> decapQueue = new ConcurrentQueue<byte[]>();
        BackgroundWorker decapWorker;

        PACKET_COUNTER packetCounter = new PACKET_COUNTER();

        #endregion

        #region IVpnPlugin Implementation

        /// <summary>
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
        /// </summary>
        /// <param name="channel">VpnChannel</param>
        public void Connect(VpnChannel channel)
        {
            try
            {
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Entering Connect.");

                
                // If we don't think the API's exist, check if they do (first connection attempt we assume they do not)
                if (!ApisExist)
                {
                    ApisExist = CheckAPIsExist(channel);

                    // If they still don't exist after checking we fail
                    if (!ApisExist)
                    {
                        throw new System.Exception("APIs not present in this version of windows, check logs for more details.");
                    }
                }

                //
                // Log a debugging message if this is a reconnect scenario
                //
                if (IsReconnect)
                {
                    LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "This is a Reconnection.");
                }

                //
                // Log channel id for reference
                //
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, String.Format("Channel Id: {0}", channel.Id.ToString()));

                //
                // Parse custom configuration from the channel config.
                //

                CustomConfiguration config = new CustomConfiguration(channel, this.IsReconnect, this.exceptionFlags);

                //
                // Create the socket which we will use to connect to a VPN server, and associate the socket with the VPN channel
                //

                if (config.transportType == VPN_PLUGIN_TRANSPORT_TYPE.VPN_PLUGIN_TRANSPORT_TYPE_DUAL)
                {
                    LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Create and associate outer tunnel transport sockets (Dual)");

                    tcpSocket = new StreamSocket();
                    udpSocket = new DatagramSocket();
                    channel.AssociateTransport(tcpSocket, udpSocket);
                }
                else if (config.transportType == VPN_PLUGIN_TRANSPORT_TYPE.VPN_PLUGIN_TRANSPORT_TYPE_UDP)
                {
                    LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Create and associate outer tunnel transport sockets (UDP)");

                    udpSocket = new DatagramSocket();
                    channel.AssociateTransport(udpSocket, null);
                }
                else if (config.transportType == VPN_PLUGIN_TRANSPORT_TYPE.VPN_PLUGIN_TRANSPORT_TYPE_TCP)
                {
                    LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Create and associate outer tunnel transport sockets (TCP)");

                    tcpSocket = new StreamSocket();
                    channel.AssociateTransport(tcpSocket, null);
                }

                //
                // Display Pre-Auth Custom UI (if requested and if this is not a reconnect)
                //
                if (config.preAuthCustomPrompts.Count > 0 &&
                    IsReconnect == false)
                {
                    LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, String.Format("We are going to display {0} pre-auth custom UI prompts.", config.preAuthCustomPrompts.Count.ToString()));

                    foreach (IReadOnlyList<IVpnCustomPrompt> customPrompt in config.preAuthCustomPrompts)
                    {
                        LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Requesting Custom UI Prompt...");
                        channel.RequestCustomPrompt(customPrompt);

                        LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Custom UI request is complete. Retrieving UI element properties...");
                        LogCustomPrompt(channel, customPrompt);
                    }
                }

                ///
                // Before a connection to the VPN server is attempted, we may need to collect authentication credentials
                // from the user.
                //

                VPN_AUTHENTICATION vPN_AUTHENTICATION = new VPN_AUTHENTICATION();
                vPN_AUTHENTICATION.authType = VpnCredentialType.UsernamePassword;
                vPN_AUTHENTICATION.expectedUser = "vpntest\\Vpn1";
                vPN_AUTHENTICATION.expectedPass = "VpnDhcp254";
                config.authentications.Add(vPN_AUTHENTICATION);

                AttemptAuthentication(channel, config);

                if (config.TestActivateForeground)
                {
                   
                    ValueSet userPass = channel.ActivateForeground("App", new ValueSet());
                    Object username;
                    Object password;

                    if (!userPass.TryGetValue("Username", out username) || !userPass.TryGetValue("Password", out password))
                    {
                        throw new System.UnauthorizedAccessException("Authentication has failed.");
                    }
                    else if (!username.Equals("username") || !password.Equals("password"))
                    {
                        throw new System.UnauthorizedAccessException("Authentication has failed.");
                    }
                }
                



                // Test exception can be thrown from here by provision <exception><func>connect_1</func><exception> 
                // This is simulating the vpn plugin hit unhandled exception and bubbled to our platform
                //
                if (exceptionFlags.exConnect_1)
                {
                    throw new NullReferenceException("This is a test exception thrown before associating transport during connect");
                }

                //
                // We should now be ready to establish a connection to a VPN server. Here we will loop through
                // the list of VPN servers specified within the VPN profile configuration until a successful connection
                // is made over the desired transport type(s)
                //
                foreach (HostName server in config.cfg.ServerHostNameList)
                {
                    //
                    // Do we need to connect to the server using TCP?
                    //
                    if (config.transportType == VPN_PLUGIN_TRANSPORT_TYPE.VPN_PLUGIN_TRANSPORT_TYPE_TCP ||
                        config.transportType == VPN_PLUGIN_TRANSPORT_TYPE.VPN_PLUGIN_TRANSPORT_TYPE_DUAL)
                    {
                        LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, String.Format("Attempting a TCP connection to VPN server: {0}", server.DisplayName));
                        LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, String.Format("Socket protection level will be: {0}", config.protectionLevel.ToString()));
                        
                        try
                        {
                            Task t = tcpSocket.ConnectAsync(server, config.portServiceName, config.protectionLevel).AsTask();
                            t.Wait();

                            // If the connection succeeds, we will reach the next line. Otherwise, we will hit the catch block below

                            config.connectedTcp = true;
                        }
                        catch (Exception ex)
                        {
                            SocketErrorStatus status = SocketError.GetStatus(ex.HResult);
                            LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, String.Format("TCP Connection failed with error: {0}.", status.ToString()));
                        }

                        // Check to see if we successfully connected using TCP

                        if (config.connectedTcp)
                        {
                            // If we only need a TCP connection, then we are done and need to exit the loop

                            if (config.transportType == VPN_PLUGIN_TRANSPORT_TYPE.VPN_PLUGIN_TRANSPORT_TYPE_TCP)
                            {
                                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "TCP connection succeeded.");
                                break;
                            }
                        }
                        else
                        {
                            // We failed to connect, so we need to loop and try the next VPN server

                            continue;
                        }
                    }

                    //
                    // Do we need to connect to the server using UDP?
                    //
                    if (config.transportType == VPN_PLUGIN_TRANSPORT_TYPE.VPN_PLUGIN_TRANSPORT_TYPE_UDP ||
                        config.transportType == VPN_PLUGIN_TRANSPORT_TYPE.VPN_PLUGIN_TRANSPORT_TYPE_DUAL)
                    {
                        LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, String.Format("Attempting a UDP connection to VPN server: {0}", server.DisplayName));

                        try
                        {
                            Task t = udpSocket.ConnectAsync(server, config.portServiceName).AsTask();
                            t.Wait();

                            // If the connection succeeds, we will reach the next line. Otherwise, we will hit the catch block below

                            config.connectedUdp = true;
                        }
                        catch (Exception ex)
                        {
                            SocketErrorStatus status = SocketError.GetStatus(ex.HResult);
                            LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, String.Format("UDP Connection failed with error: {0}.", status.ToString()));
                        }

                        // Check to see if we successfully connected using UDP

                        if (config.connectedUdp)
                        {
                            // We successfully connected, so now we can exit the loop
                            LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "UDP connection succeeded.");
                            break;
                        }
                        else
                        {
                            // We failed to connect UDP. Check to see if there is any cleanup to take care of.

                            if (config.transportType == VPN_PLUGIN_TRANSPORT_TYPE.VPN_PLUGIN_TRANSPORT_TYPE_DUAL)
                            {
                                // ouch tough situation. If we got here then TCP connected but UDP did not. Before looping to try the next VPN server, we need to
                                // to first disconnect the TCP socket (we don't want the TCP and UDP sockets connected to different VPN servers!)

                                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "UDP connection failed. Disconnecting the TCP socket.");

                                tcpSocket.Dispose();
                                //tcpSocket = null;

                                config.connectedTcp = false;
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
                if ((config.transportType == VPN_PLUGIN_TRANSPORT_TYPE.VPN_PLUGIN_TRANSPORT_TYPE_DUAL && (!config.connectedTcp || !config.connectedUdp)) ||
                     (config.transportType == VPN_PLUGIN_TRANSPORT_TYPE.VPN_PLUGIN_TRANSPORT_TYPE_TCP && !config.connectedTcp) ||
                     (config.transportType == VPN_PLUGIN_TRANSPORT_TYPE.VPN_PLUGIN_TRANSPORT_TYPE_UDP && !config.connectedUdp))
                {
                    LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Error: Unable to establish a VPN server connection.");

                    // If we have any connected sockets, close them before exiting

                    if (config.connectedTcp)
                    {
                        LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Closing TCP socket (cleaning up).");
                        tcpSocket.Dispose();
                        tcpSocket = null;
                    }

                    if (config.connectedUdp)
                    {
                        LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Closing UDP socket (cleaning up).");
                        udpSocket.Dispose();
                        udpSocket = null;
                    }

                    throw new OperationCanceledException("Unable to establish a server connection.");
                }


                //
                // Check System health
                //
                // We do this in a try/catch because attempting to check the health of a machine with napagent service
                // disabled (or the relevant enforcement client disabled) will result in a exception
                //
                try
                {
                    LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Checking system health...");

                    config.healthStatus = channel.SystemHealth;
                    if (config.healthStatus != null)
                    {
                        Windows.Storage.Streams.Buffer healthBlob = config.healthStatus.StatementOfHealth;

                        if (healthBlob != null)
                        {
                            LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Received statement of health - length: " + healthBlob.Length);
                            LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, ConvertBufferToHexString(healthBlob));
                        }
                        else
                        {
                            LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Warning: Received null for system health statement of health.");
                        }
                    }
                    else
                    {
                        LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Warning: Received null for system health.");
                    }
                }
                catch (Exception ex)
                {
                    //
                    // Expected to be "Access Denied" if the napagent service is stopped or
                    // "The entity is disabled with the napagent service" if the relevant enforcement client is not enabled via napclcfg.msc
                    //
                    LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Warning: Exception caught during system health check: " + ex.Message);
                }

                //
                // Display Post-Auth Custom UI (if requested and if this is not a reconnect)
                //
                if (config.postAuthCustomPrompts.Count > 0 &&
                    IsReconnect == false)
                {
                    LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, String.Format("We are going to display {0} custom UI prompts.", config.postAuthCustomPrompts.Count.ToString()));

                    foreach (IReadOnlyList<IVpnCustomPrompt> customPrompt in config.postAuthCustomPrompts)
                    {
                        LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Requesting Custom UI Prompt...");
                        channel.RequestCustomPrompt(customPrompt);

                        LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Custom UI request is complete. Retrieving UI element properties...");
                        LogCustomPrompt(channel, customPrompt);
                    }
                }

                // Test exception can be thrown from here by provision <exception><func>connect_2</func><exception> 
                // This is simulating the vpn plugin hit unhandled exception and bubbled to our platform
                //
                if (exceptionFlags.exConnect_2)
                {
                    throw new NullReferenceException("This is a test exception thrown after associating transport but before channel start during connect");
                }

                //
                // We have an established connection to the VPN server, so now we ask the platform to start the VPN channel
                //
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Starting the VPN channel.");

                //
                // Convert the client IP address into a hostname list for passing to the channel->Start call
                //
                IReadOnlyList<HostName> assignedV4AddressList = new List<HostName>()
                {
                    new Windows.Networking.HostName(config.clientIpV4)
                };

                IReadOnlyList<HostName> assignedV6AddressList = null;
                if (!String.IsNullOrEmpty(config.clientIpV6))
                {
                    assignedV6AddressList = new List<HostName>()
                    {
                        new Windows.Networking.HostName(config.clientIpV6)
                    };
                }

                if (config.transportType == VPN_PLUGIN_TRANSPORT_TYPE.VPN_PLUGIN_TRANSPORT_TYPE_DUAL)
                {
                    //v2 Addition
                    if (config.IsV2)
                    {
                        channel.StartWithTrafficFilter(assignedV4AddressList, // client ipv4 address
                            assignedV6AddressList, // client ipv6 address
                            null, // Vpn interface Id, passing as null for now
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
                        channel.Start(assignedV4AddressList, // client ipv4 address
                            assignedV6AddressList, // client ipv6 address
                            null, // Vpn interface Id, passing as null for now
                            config.routeAssignment, // route assignment
                            config.namespaceAssignment, // namespace assignment
                            1500, // mtu size
                            config.maxFrameSize, // max frame size
                            true, // optimize for low cost networks
                            tcpSocket, // our main tunnel transport socket
                            udpSocket); // optional second tunnel transport socket
                    }
                }
                else if (config.transportType == VPN_PLUGIN_TRANSPORT_TYPE.VPN_PLUGIN_TRANSPORT_TYPE_UDP)
                {
                    //v2 Addition
                    if (config.IsV2)
                    {
                        channel.StartWithTrafficFilter(assignedV4AddressList, // client ipv4 address
                            assignedV6AddressList, // client ipv6 address
                            null, // Vpn interface Id, passing as null for now
                            config.routeAssignment, // route assignment
                            config.domainnameAssignment, // namespace assignment
                            1500, // mtu size
                            config.maxFrameSize, // max frame size
                            true, // optimize for low cost networks
                            udpSocket, // our main tunnel transport socket
                            null,     // optional second tunnel transport socket
                            config.trafficFilterAssignment);
                    }
                    else
                    {
                        channel.Start(assignedV4AddressList, // client ipv4 address
                            assignedV6AddressList, // client ipv6 address
                            null, // Vpn interface Id, passing as null for now
                            config.routeAssignment, // route assignment
                            config.namespaceAssignment, // namespace assignment
                            1500, // mtu size
                            config.maxFrameSize, // max frame size
                            true, // optimize for low cost networks
                            udpSocket, // our main tunnel transport socket
                            null); // optional second tunnel transport socket
                    }
                }
                else
                {
                    //v2 Addition
                    if (config.IsV2)
                    {
                        channel.StartWithTrafficFilter(assignedV4AddressList, // client ipv4 address
                            assignedV6AddressList, // client ipv6 address
                            null, // Vpn interface Id, passing as null for now
                            config.routeAssignment, // route assignment
                            config.domainnameAssignment, // namespace assignment
                            1500, // mtu size
                            config.maxFrameSize, // max frame size
                            true, // optimize for low cost networks
                            tcpSocket, // our main tunnel transport socket
                            null,    // optional second tunnel transport socket
                            config.trafficFilterAssignment);
                    }
                    else
                    {
                        channel.Start(assignedV4AddressList, // client ipv4 address
                            assignedV6AddressList, // client ipv6 address
                            null, // Vpn interface Id, passing as null for now
                            config.routeAssignment, // route assignment
                            config.namespaceAssignment, // namespace assignment
                            1500, // mtu size
                            config.maxFrameSize, // max frame size
                            true, // optimize for low cost networks
                            tcpSocket, // our main tunnel transport socket
                            null); // optional second tunnel transport socket
                    }
                }
                // Set this bool to true so that next time we are called to connect we will know it is really a reconnection
                IsReconnect = true;
                //
                // Test exception can be thrown from here by provision <exception><func>connect_3</func><exception> 
                // This is simulating the vpn plugin hit unhandled exception and bubbled to our platform
                //
                if (exceptionFlags.exConnect_3)
                {
                    throw new NullReferenceException("This is a test exception thrown after channel start during connect");
                }
            }
            catch (Exception ex)
            {
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, String.Format("Exception caught during Connect: {0}", ex.Message));
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, String.Format("Exception stack trace: {0}", ex.StackTrace));
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, String.Format("Exception source: {0}", ex.Source));
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, String.Format("Inner Exception: {0}", ex.InnerException));
                //
                // Set the error message and re-throw this fatal error. Note that we do not set the error message for reconnection
                // attempts.
                //
                // These error messages will be displayed to the user in both the VPN flyout and settings page when we fail to connect
                // We recommend using the error messages produced by the VPN platform, rather than custom error messages.
                //
                if (IsReconnect == false)
                {
                    channel.SetErrorMessage(ex.Message);
                }

                throw;
            }
            finally
            {
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Leaving Connect.");
            }
        }

        

        /// <summary>
        /// 
        /// Disconnect implementation
        /// 
        /// - Invoked by the platform (via our VpnBackgroundTask while in the call to ProcessEventAsync) when the VPN connection
        ///   is no longer needed and should be disconnected
        /// 
        /// - During this call, it is expected that you will at least do the following:
        ///   - Stop the VPN channel
        ///   
        /// </summary>
        /// <param name="channel">VpnChannel</param>
        public void Disconnect(VpnChannel channel)
        {
            try
            {
                Debug.WriteLine("Entering Disconnect");
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Entering Disconnect.");

                //
                // Test exception can be thrown from here by provision <exception><func>disconnect</func><exception> 
                // This is simulating the vpn plugin hitting a unhandled exception and being bubbled up to our platform
                //
                if (exceptionFlags.exDisconnect)
                {
                    throw new NullReferenceException("This is a test exception thrown during disconnect");
                }

                // If we are called to disconnect, then the next connect call is not really a reconnect

                IsReconnect = false;

                gDecapState = new VPN_PLUGIN_DECAP_STATE();
                if (gDecapState.currentSize == 0)
                {
                    gDecapState.currentPartialPacket = new byte[PARTIAL_PACKET_SIZE];
                }

                channel.Stop();

                //reset counter and decap state
                packetCounter = new PACKET_COUNTER();
                gDecapState = new VPN_PLUGIN_DECAP_STATE();
                if (gDecapState.currentSize == 0)
                {
                    gDecapState.currentPartialPacket = new byte[PARTIAL_PACKET_SIZE];
                }
                updateSharedMemory();
            }
                
            catch (Exception ex)
            {
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, String.Format("Exception caught during Disconnect: {0}", ex.Message));

                //
                // If we are in exception mode, we should re-throw here for testing purposes
                //
                if (exceptionFlags.exMode)
                {
                    throw;
                }
            }
            finally
            {
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Leaving Disconnect.");
            }
        }

        /// <summary>
        /// 
        /// Encapsulate implementation
        /// 
        /// - Invoked by the platform (via our VpnBackgroundTask while in the call to ProcessEventAsync) when
        ///   outbound packets need to be encapsulated prior to them being sent to the VPN server
        ///   
        /// - For this sample, our protocol is IP (TCP over IP) with a single control byte tagged on the front
        ///     - We use asynchronous encapsulation, see EncapWorker_DoWork
        /// 
        /// - During this call, it is expected that you will at least do the following:
        ///   - Populate the encapsulatedPacketList with all of the encapsulated packets you wish to send to the VPN server
        ///   
        /// </summary>
        /// <param name="channel">VpnChannel</param>
        /// <param name="packets">VpnPacketBufferList</param>
        /// <param name="encapulatedPackets">VpnPacketBufferList</param>
        public void Encapsulate(VpnChannel channel,
                                VpnPacketBufferList packets,
                                VpnPacketBufferList encapulatedPackets)
        {
            VpnPacketBuffer buffer;

            try
            {
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, "Entering Encapsulate.");

                //
                // Test exception can be thrown from here by provision <exception><func>encapsulate</func><exception> 
                // This is simulating the vpn plugin hitting a unhandled exception and being bubbled to our platform
                //
                if (exceptionFlags.exEncapsulate)
                {
                    throw new NullReferenceException("This is a test exception thrown during encapsulate");
                }

                if (encapWorker == null)
                {
                    encapWorker = new BackgroundWorker();
                    encapWorker.WorkerSupportsCancellation = false;
                    encapWorker.DoWork += new DoWorkEventHandler(EncapWorker_DoWork);
                }

                //
                // For this sample, our protocol is IP (TCP over IP) with no encapsulation,
                // so we will simply be take the packets that need to be encapsulated from the 
                // packetList and append them to the encapsulatedPacketList so that they will be
                // sent "as-is" to the VPN server. 
                //
                // We use RemoveAtBegin to take packets from the packetList, to ensure that the packet
                // ordering is maintained.
                //

                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, String.Format("There are {0} packets to encapsulate.", packets.Size.ToString()));

                // Enter the encapsulation loop

                while (packets.Size > 0)
                {
                    buffer = packets.RemoveAtBegin();

                    encapQueue.Enqueue(buffer);

                    // Loop so that we receive the next packet or exit (if we are done)

                    buffer = null;

                    LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_HIGH, String.Format("Finished with the current packet ({0} remaining)", packets.Size.ToString()));
                }

                //Tell worker thread it has work
                if (!encapWorker.IsBusy)
                {
                    encapWorker.RunWorkerAsync(channel);
                }
            }
            catch (Exception ex)
            {
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, String.Format("Exception caught during Encapsulate: {0}", ex.Message));

                // If we are in exception mode, we should re-throw here for testing purposes

                if (exceptionFlags.exMode)
                {
                    throw;
                }
            }
            finally
            {
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, "Leaving Encapsulate.");
            }
        }

        /// <summary>
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
        ///     - We demo asynchronous decapuslation, see DecapWorker_DoWork
        /// 
        /// - During this call, it is expected that you will at least do the following:
        ///   - Populate the decapsulatedPackets with all of the decapsulated packets you wish to deliver
        ///   
        /// </summary>
        /// <param name="channel">VpnChannel</param>
        /// <param name="encapPacket">VpnPacketBuffer</param>
        /// <param name="decapsulatedPackets">VpnPacketBufferList</param>
        /// <param name="controlPacketsToSend">VpnPacketBufferList</param>
        public void Decapsulate(VpnChannel channel,
                                VpnPacketBuffer encapBuffer,
                                VpnPacketBufferList decapsulatedPackets,
                                VpnPacketBufferList controlPacketsToSend)
        {
            try
            {
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, "Entering Decapsulate.");

                Windows.Storage.Streams.Buffer spFrameBuffer;
                byte[] pBytesRawFrameBuffer = null;    
                
                //
                // Test exception can be thrown from here by provision <exception><func>decapsulate</func><exception> 
                // This is simulating the vpn plugin hitting a unhandled exception and being bubbled to our platform
                //
                if (exceptionFlags.exDecapsulate)
                {
                    throw new NullReferenceException("This is a test exception thrown during decapsulate");
                }

                if (decapWorker == null)
                {
                    decapWorker = new BackgroundWorker();
                    decapWorker.WorkerSupportsCancellation = false;
                    decapWorker.DoWork += new DoWorkEventHandler(DecapWorker_DoWork);
                }

                //
                // We are being called to Decapsulate the packets contained within the encapBuffer, so first we will
                // store a reference to the buffer length and we will get access to raw byte array of the frame buffer
                //
                spFrameBuffer = encapBuffer.Buffer;
                pBytesRawFrameBuffer = VpnPluginGetRawByteBuffer(spFrameBuffer);
                
                decapQueue.Enqueue(pBytesRawFrameBuffer);

                //Tell worker thread it has work
                if (!decapWorker.IsBusy)
                {
                    decapWorker.RunWorkerAsync(channel);
                }
                
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_HIGH, "Decapsulate was called with an encapBuffer length of " + spFrameBuffer.Length.ToString());

                // If buffer capture is enabled, output the encapbuffer
                if (logger.loggingSettings.bufferCapture)
                {
                    LogPacketBuffer(channel, "encapBuffer", spFrameBuffer);
                }  
            }
            catch (Exception ex)
            {
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, String.Format("Exception caught during Decapsulate: {0}", ex.Message));
            }
            finally
            {
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, "Leaving Decapsulate.");
            }
        }

        /// <summary>
        /// 
        /// GetKeepAlivePayload implementation
        /// 
        /// - Invoked by the platform (via our VpnBackgroundTask while in the call to ProcessEventAsync) to
        ///   provide an opportunity to craft and send a keep alive packet to the connected VPN server.
        ///   
        /// - During this call, it is expected that you will at least do the following:
        ///   - Optionally, craft a keep alive packet (VpnPacketBuffer) to be sent to the VPN server
        ///   
        /// </summary>
        /// <param name="channel">VpnChannel</param>
        /// <param name="keepAlivePacket">VpnPacketBuffer</param>
        public void GetKeepAlivePayload(VpnChannel channel,
                                        out VpnPacketBuffer keepAlivePacket)
        {
            keepAlivePacket = null;
            try
            {
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Entering GetKeepAlivePayload.");

                channel.RequestVpnPacketBuffer(VpnDataPathType.Send, out keepAlivePacket);
                 keepAlivePacket.Buffer.Length = 1;

                Stream stream = keepAlivePacket.Buffer.AsStream();
                stream.Seek(0, SeekOrigin.Begin);
                stream.SetLength(1);
                stream.WriteByte( (byte) VPN_CONTROL.VPN_CONTROL_KEEP_ALIVE);
                stream.Dispose();
                
                packetCounter.TotalSent++;
                packetCounter.TotalControlSent++;
                packetCounter.TotalKeepAliveSent++;
                updateSharedMemory();
            }
            catch (Exception ex)
            {
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, String.Format("Exception caught during GetKeepAlivePayload: {0}", ex.Message));
            }
            finally
            {
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Leaving GetKeepAlivePayload.");
            }
        }

        #endregion

        #region Workers
        private void EncapWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            VpnChannel channel = (VpnChannel)e.Argument;
            LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, "Entering encapWorker_DoWork.");
            VpnPacketBuffer buffer;

            //used for packetCounter 
            int totalUDP = 0;
            int totalSent = 0;
            int totalBytes = 0;

            while (!encapQueue.IsEmpty)
            {
                if (encapQueue.TryDequeue(out buffer))
                {
                    LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, "Appending vpn packet buffers.");
                    
                    byte[] inBuffer = buffer.Buffer.ToArray();
                    byte[] outBuffer = new byte[inBuffer.Length + 1];
                    


                    outBuffer[0] = (int) VPN_CONTROL.VPN_CONTROL_PACKET;
                    
                    Array.Copy(inBuffer, 0, outBuffer, 1, inBuffer.Length);

                    Windows.Storage.Streams.Buffer buf = buffer.Buffer;

                    BufferCopy(
                            ref outBuffer,
                            0,
                            ref buf,
                            0,
                            outBuffer.Length
                            );

                    buf.Length = (uint)outBuffer.Length;

                    PacketUtils.FULL_HEADER_V4 packet = PacketUtils.PinV4FullHeader(outBuffer);

                    if (packet.IpHeader.Protocol == PacketUtils.UDP_PROTOCOL_ID)
                    {
                        totalUDP++;
                    }
                    totalSent++;
                    totalBytes += outBuffer.Length;

                    //
                    // If requested, output the packet for debugging purposes
                    //
                    if (logger.loggingSettings.packetCapture)
                    {
                        LogPacket(channel, false, buffer);
                    }

                    channel.AppendVpnSendPacketBuffer(buffer);
                    if (ShouldFlushPacketBuffer())
                    {
                        LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, "Flushing send packet buffers.");
                        channel.FlushVpnSendPacketBuffers();

                        //adjust packetCounter, packets only sent when we flush the buffer
                        packetCounter.TotalUDPSent += totalUDP;
                        packetCounter.TotalSent += totalSent;
                        packetCounter.TotalBytesSent += totalBytes;
                        totalUDP = 0;
                        totalSent = 0;
                        totalBytes = 0;

                        updateSharedMemory();
                    }
                }
            }
        }

        private bool ShouldFlushPacketBuffer()
        {
            return true;
        }

        private void AppendAndFlushReceivePackets(VpnChannel channel, VpnPacketBuffer spCurrentPacket)
        {
            channel.AppendVpnReceivePacketBuffer(spCurrentPacket);
            if (ShouldFlushPacketBuffer())
            {
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, "Flushing receive packet buffers.");
                channel.FlushVpnReceivePacketBuffers();
                updateSharedMemory();
            }
        }

        private void DecapWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            VpnChannel channel = (VpnChannel)e.Argument;
            
            LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, "Entering DecapWorker_DoWork.");
            byte[] pBytesRawFrameBuffer = null;

            UInt32 length = 0;

            while (!decapQueue.IsEmpty)
            {
                if (decapQueue.TryDequeue(out pBytesRawFrameBuffer))
                {
                    length = (uint)pBytesRawFrameBuffer.Length;

                    LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_HIGH, "Decapsulate was called with an encapBuffer length of " + length.ToString());

                    //
                    // Next we need to see if we are starting to decapsulate a new packet or if there is a 
                    // partial packet that we need to continue decapsulating because we didn't enough data to complete
                    // the packet during the previous invocation. 
                    //
                    // We always store the state of the current packet we are decapsulating within our gDecapState member.
                    // Therefore, we need to look at gDecapState now to see if its currentSize is greater than 0 (which would
                    // indicate that we have a partial packet to continue with) and to see whether we even have enough
                    // of the partial packet to be able to look at the IPv4 header and determine the full length of the packet
                    // (VALID_LENGTH represents the amount of data we must have in order to be able to read the
                    // TotalLength field of the IPv4 header).
                    // 

                    //
                    // If we just had a single byte (the control byte) left
                    // We need to determine the packet type
                    //
                    if (gDecapState.currentSize == 1)
                    {
                        // Just need to copy 1 byte to determine packet version
                        Array.Copy(
                            pBytesRawFrameBuffer, //source
                            0, // source index
                            gDecapState.currentPartialPacket, // destination
                            Convert.ToInt32(gDecapState.currentSize), // destination index
                            Convert.ToInt32(1)
                            );
                        gDecapState.currentSize = 2;

                        MoveAlongFrameBuffer(ref pBytesRawFrameBuffer, 1, ref length);


                        bool isV6 = false;
                        ProcessPacketVersion(channel, gDecapState.currentPartialPacket, 2, ref gDecapState, ref isV6);
                        gDecapState.isV6 = isV6;
                    }

                    //
                    // If we've already consumed the whole frame buffer, then we are done. We still haven't finish decapsulating
                    // the current packet, but it will be stored in m_DecapState and we will continue decap'ing when this
                    // method is invoked again with more data.
                    //
                    if (length == 0)
                    {
                        continue;
                    }

                    //Attempt to figure out length of packet
                    if (gDecapState.currentSize != 0 &&
                        ((!gDecapState.isV6 && (gDecapState.currentSize < VALID_LENGTH)) ||
                        (gDecapState.isV6 && (gDecapState.currentSize < VALID_LENGTH_V6))))
                    {
                        LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_HIGH, "Continuing a partial packet (need to complete the ip header).");

                        //
                        // If we are here, then we ARE continuing with a partial packet, but it looks like we don't yet
                        // have enough of the IPv4 header to even know the full length of the packet. So the first thing
                        // we will do is copy over enough data from the frame byte array so that we can at least find out
                        // the total length of the packet.
                        //
                        uint validLength = (gDecapState.isV6) ? VALID_LENGTH_V6 : VALID_LENGTH;
                        uint lengthToCopy = Math.Min(validLength, length);

                        Array.Copy(
                            pBytesRawFrameBuffer, //source
                            0, // source index
                            gDecapState.currentPartialPacket, // destination
                            Convert.ToInt32(gDecapState.currentSize), // destination index
                            Convert.ToInt32(lengthToCopy) // length
                            );

                        gDecapState.currentSize += lengthToCopy;

                        // Do we now have enough IPv4 header data to determine the full packet length?
                        if (!gDecapState.isV6 && (gDecapState.currentSize >= VALID_LENGTH))
                        {
                            //
                            // Yes, we have enough data, so get the total length of the packet in host order and store
                            // it in the packetHostOrderTotalLength member for later use
                            //
                            ushort totalLengthBytes = PacketUtils.PinV4FullHeader(gDecapState.currentPartialPacket).IpHeader.TotalLengthBytes;
                            gDecapState.packetHostOrderTotalLength = PacketUtils.ReverseByteOrder(totalLengthBytes);
                        }

                        // Do we now have enough IPv6 header data to determine the full packet length?
                        if (gDecapState.isV6 && (gDecapState.currentSize >= VALID_LENGTH_V6))
                        {
                            //
                            // Yes, we have enough data, so get the total length of the packet in host order and store
                            // it in the packetHostOrderTotalLength member for later use
                            //
                            ushort PayloadLength = PacketUtils.PinV6FullHeader(gDecapState.currentPartialPacket).IpHeader.PayloadLength;
                            gDecapState.packetHostOrderTotalLength = (ushort)(PacketUtils.ReverseByteOrder(PayloadLength) + IPV6_HEADER_LENGTH);
                        }

                        MoveAlongFrameBuffer(ref pBytesRawFrameBuffer, lengthToCopy, ref length);
                    }

                    //
                    // If we've already consumed the whole frame buffer, then we are done. We still haven't finish decapsulating
                    // the current packet, but it will be stored in m_DecapState and we will continue decap'ing when this
                    // method is invoked again with more data.
                    //
                    if (length == 0)
                    {
                        continue;
                    }

                    if (gDecapState.currentSize != 0)
                    {
                        LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_HIGH, String.Format("Full length of the partial packet is known ({0}). See if we have enough data to satisfy the packet.", gDecapState.packetHostOrderTotalLength.ToString()));
                    }

                    //
                    // If we are still working on a partial packet, then we should at least know the full length of the packet
                    // now, so we need to check and see if we actually have enough remaining data in the frame to satisfy
                    // the full packet.
                    //
                    if (gDecapState.currentSize != 0 &&
                        ((!gDecapState.isV6 && (gDecapState.currentSize >= VALID_LENGTH)) ||
                        (gDecapState.isV6 && (gDecapState.currentSize >= VALID_LENGTH_V6))) &&
                        (gDecapState.packetHostOrderTotalLength + 1 - gDecapState.currentSize) > length) //plus 1 for control packet
                    {
                        LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_HIGH, "We do NOT have enough data to satisfy the packet.");

                        //
                        // It looks like we don't have enough data to satisfy the full pending packet, so just copy all of the
                        // data that we have in the frame byte array to m_DecapState and then return. We will continue decap'ing
                        // the partial packet when we get invoked next time with more data.
                        //
                        Array.Copy(
                            pBytesRawFrameBuffer, //source
                            0, // source index
                            gDecapState.currentPartialPacket, // destination
                            Convert.ToInt32(gDecapState.currentSize), // destination index
                            Convert.ToInt32(length) // length
                            );

                        gDecapState.currentSize += length;

                        continue;
                    }

                    //
                    // If we are still working on a partial packet, then we must now have enough data to satisfy the full
                    // packet.
                    //
                    if (gDecapState.currentSize != 0 &&
                        ((!gDecapState.isV6 && (gDecapState.currentSize >= VALID_LENGTH)) ||
                        (gDecapState.isV6 && (gDecapState.currentSize >= VALID_LENGTH_V6))) &&
                        (gDecapState.packetHostOrderTotalLength + 1 - gDecapState.currentSize) <= length) //+ 1 for control packet
                    {
                        LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_HIGH, "We have enough data to satisfy the packet.");

                        byte[] completePacket = new byte[gDecapState.packetHostOrderTotalLength + 1]; //plus one since the host order total length does not contain control packet

                        // Copy what we had saved of the partial packet from gDecapState
                        Array.Copy(
                            gDecapState.currentPartialPacket,
                            0,
                            completePacket,
                            0,
                            Convert.ToInt32(gDecapState.currentSize)
                            );

                        // Then copy the remainder of the packet from the frame buffer
                        Array.Copy(
                            pBytesRawFrameBuffer,
                            0,
                            completePacket,
                            Convert.ToInt32(gDecapState.currentSize),
                            Convert.ToInt32(gDecapState.packetHostOrderTotalLength + 1 - gDecapState.currentSize)
                            );

                        FinishWithCurrentPacket(channel, ref gDecapState, ref completePacket);

                        //
                        // Move along the frame buffer byte array so that we are ready to work on the next packet
                        // and update Length to represent the remaining number of bytes still left to read in the frame
                        //
                        MoveAlongFrameBuffer(ref pBytesRawFrameBuffer, (uint)(gDecapState.packetHostOrderTotalLength + 1 - gDecapState.currentSize), ref length);

                        LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_HIGH, "We are done with the partial packet (length: " + completePacket.Length.ToString() + ").");
                    }

                    
                    //reset decapState since we finished the partial packet (or we never had one)
                    gDecapState = new VPN_PLUGIN_DECAP_STATE();
                    if (gDecapState.currentSize == 0)
                    {
                        gDecapState.currentPartialPacket = new byte[PARTIAL_PACKET_SIZE];
                    }

                    //
                    // If we've already consumed the whole frame buffer, then we are done
                    //
                    if (length == 0)
                    {
                        continue;
                    }

                    LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_HIGH, "Starting to process the next packet.");

                    //
                    // If we reach this point, we must be starting to process a new packet
                    //
                    // Look at the frame bytes to see if we have enough of the next IPv4/IPv6 header to understand
                    // the full length of the next packet. Again, VALID_LENGTH represents the amount of data we must
                    // have in order to be able to read the TotalLength/PayloadLength field of the IPv4/IPv6 header
                    //

                    //We use this temporary currentState for the current packets, if we end up having a split packet we use gDecapState later
                    VPN_PLUGIN_DECAP_STATE gCurrentState = new VPN_PLUGIN_DECAP_STATE();
                    if (gCurrentState.currentSize == 0)
                    {
                        gCurrentState.currentPartialPacket = new byte[PARTIAL_PACKET_SIZE];
                    }

                    Array.Copy(
                        pBytesRawFrameBuffer, //source
                        0, // source index
                        gCurrentState.currentPartialPacket, // destination
                        Convert.ToInt32(gCurrentState.currentSize), // destination index
                        (int) Math.Min(PARTIAL_PACKET_SIZE, length) // length
                        );

                    if(VPN_CONTROL.VPN_CONTROL_DISCONNECT == ProcessControlByte(channel, ref pBytesRawFrameBuffer, ref gCurrentState, ref length))
                    {
                        return;
                    }

                    bool isV6Next = false;

                    ProcessPacketVersion(channel, pBytesRawFrameBuffer, length, ref gCurrentState, ref isV6Next);

                    //
                    // We now enter a loop in which we will continue to process all of the fully-transmitted packets
                    // within the frame buffer. The loop will exit when we finish processing all of the packets or 
                    // reach a point at which we do not have enough data to fully satisfy the next packet.
                    //
                    LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_HIGH, "About to enter packet processing loop.");

                    while (((isV6Next && (length > VALID_LENGTH_V6)) ||
                            (!isV6Next && (length > VALID_LENGTH))) &&
                            gCurrentState.packetHostOrderTotalLength + 1 <= length)
                    {
                        FinishWithCurrentPacket(channel, ref gCurrentState, ref pBytesRawFrameBuffer);

                        MoveAlongFrameBuffer(ref pBytesRawFrameBuffer, (uint) (gCurrentState.packetHostOrderTotalLength + 1), ref length);

                        // Copy in packet to state
                        Array.Copy(
                            pBytesRawFrameBuffer, //source
                            0, // source index
                            gCurrentState.currentPartialPacket, // destination
                            0, // destination index
                            (int) Math.Min(PARTIAL_PACKET_SIZE, length) // length
                            );

                        // If buffer length is already down to 0, it means that we finished processing the whole buffer and we can exit the loop
                        if (length == 0)
                        {
                            break;
                        }

                        ProcessControlByte(channel, ref pBytesRawFrameBuffer, ref gCurrentState, ref length);

                        // If buffer length is already down to 0, it means that we finished processing the whole buffer and we can exit the loop
                        if (length == 0)
                        {
                            break;
                        }

                        //All we know is next packet contains actual packet (control byte is VPN_CONTROL.VPN_CONTROL_PACKET)
                        if (length == 1)
                        {
                            break;
                        }
                        ProcessPacketVersion(channel, pBytesRawFrameBuffer, length, ref gCurrentState, ref isV6Next);

                        LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_HIGH, "Looping.");
                    }

                    LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_HIGH, "Exiting packet processing loop.");

                    //
                    // If length == 0, we're done, otherwise
                    // it looks like we do have a partial packet which intersected the frame, so we store the partial
                    // packet in m_DecapState. We will continue decap'ing the partial packet when we get invoked next
                    // time with more data.
                    //
                    if (length != 0)
                    {

                        LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_HIGH, String.Format("We have a partial packet to store. Length remaining is {0}.", length.ToString()));

                        gDecapState.currentPartialPacket = new byte[PARTIAL_PACKET_SIZE];

                        Array.Copy(
                            pBytesRawFrameBuffer, //src
                            0, // src index
                            gDecapState.currentPartialPacket, // dest
                            0, // dest index
                            Convert.ToInt32(length) // length
                            );

                        gDecapState.currentSize = length;

                        if (length == 1)
                        {
                            continue;
                        }

                        LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_HIGH, "Determining Packet type for partial packet.");
                        ProcessPacketVersion(channel, pBytesRawFrameBuffer, length, ref gDecapState,ref isV6Next);
                        gDecapState.isV6 = isV6Next;
                    }
                }
            }
            LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, "Leaving DecapWorker_DoWork.");
        }

        #region Decap Worker Helper Methods

        internal void FinishWithCurrentPacket(VpnChannel channel, ref VPN_PLUGIN_DECAP_STATE state, ref byte[] pBytesRawFrameBuffer)
        {
            VpnPacketBuffer spCurrentPacket;
            Windows.Storage.Streams.Buffer spPacketBuffer;
            //
            // Request a VpnPacketBuffer from the platform, this is the buffer which we will populate with the
            // next full packet. The VpnPacketBuffer will then be appended to the decapsulatedPackets list ready for
            // delivery
            //
            channel.RequestVpnPacketBuffer(VpnDataPathType.Receive, out spCurrentPacket);
            spPacketBuffer = spCurrentPacket.Buffer;

            // Copy the full packet from the frame to the packet buffer, minus control byte
            BufferCopy(
                ref pBytesRawFrameBuffer,
                1,
                ref spPacketBuffer,
                0,
                state.packetHostOrderTotalLength
                );

            //
            // Set the packet buffer length to the full length of the packet and append the packet to the 
            // decapsulatedPackets list ready for delivery.
            //
            spPacketBuffer.Length = (uint)(state.packetHostOrderTotalLength);

            // Log the packet if packet capture is enabled
            if (logger.loggingSettings.packetCapture)
            {
                LogPacket(channel, true, spCurrentPacket);
            }

            // If buffer capture is enabled, output the current packet
            if (logger.loggingSettings.bufferCapture)
            {
                LogPacketBuffer(channel, "Current Packet", spPacketBuffer);
            }

            // We are done with this packet!
            AppendAndFlushReceivePackets(channel, spCurrentPacket);

            packetCounter.TotalReceived++;
            packetCounter.TotalBytesReceived += (state.packetHostOrderTotalLength + 1); //plus one since the host order total length does not contain control packet

            LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_HIGH, "We are done with the current packet (length: " + spPacketBuffer.Length.ToString() + ").");
        }

        //
        // We have at least 2 byte, which is enough for us to figure out the version
        // Look at the frame raw bytes and see if we have enough of the next IP header to understand the full length of the
        // next packet.
        //
        internal void ProcessPacketVersion(VpnChannel channel, byte[] pBytesRawFrameBuffer, uint length, ref VPN_PLUGIN_DECAP_STATE state, ref bool isV6Next)
        {
            if (IsV6Packet(channel, pBytesRawFrameBuffer))
            {
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_HIGH, "Decapsulating v6 packet.");

                if (length >= VALID_LENGTH_V6)
                {
                    LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_HIGH, "IPv6: We have enough data to get the length of the next packet.");

                    //
                    // Yes, we have enough data, so get the total length of the packet in host order and store
                    // it in the packetHostOrderTotalLength member for later use
                    //
                    ushort PayloadLength = PacketUtils.PinV6FullHeader(state.currentPartialPacket).IpHeader.PayloadLength;
                    state.packetHostOrderTotalLength = (ushort)(PacketUtils.ReverseByteOrder(PayloadLength) + IPV6_HEADER_LENGTH);
                }

                isV6Next = true;
            }
            else
            {
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_HIGH, "Decapsulating v4 packet.");

                if (length >= VALID_LENGTH)
                {
                    LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_HIGH, "IPv4: We have enough data to get the length of the next packet.");

                    //
                    // Yes, we have enough data, so get the total length of the packet in host order and store
                    // it in the packetHostOrderTotalLength member for later use
                    //
                    ushort totalLengthBytes = PacketUtils.PinV4FullHeader(state.currentPartialPacket).IpHeader.TotalLengthBytes;
                    state.packetHostOrderTotalLength = PacketUtils.ReverseByteOrder(totalLengthBytes);
                }

                isV6Next = false;
            }
        }

        internal VPN_CONTROL ProcessControlByte(VpnChannel channel, ref byte[] pBytesRawFrameBuffer, ref VPN_PLUGIN_DECAP_STATE state, ref uint length)
        {
            VPN_CONTROL control = GetAndHandleControlByte(channel, pBytesRawFrameBuffer);

            while (VPN_CONTROL.VPN_CONTROL_PACKET != control)
            {
                packetCounter.TotalReceived++;
                packetCounter.TotalControlReceived++;
                packetCounter.TotalBytesReceived++;

                if (control == VPN_CONTROL.VPN_CONTROL_DISCONNECT)
                {
                    return control;
                }
                //It was some other control message, so now we continue
                
                MoveAlongFrameBuffer(ref pBytesRawFrameBuffer, 1, ref length);

                // Copy in packet to state
                Array.Copy(
                    pBytesRawFrameBuffer, //source
                    0, // source index
                    state.currentPartialPacket, // destination
                    0, // destination index
                    (int) Math.Min(length, PARTIAL_PACKET_SIZE) // length
                    );

                control = GetAndHandleControlByte(channel, pBytesRawFrameBuffer);
            }

            return control;
        }


        //shift the frame buffer along n bytes and decrease the total length by the shift
        private void MoveAlongFrameBuffer(ref byte[] pBytesRawFrameBuffer, uint shift, ref uint length)
        {
            length -= shift;

            byte[] newArray = new byte[pBytesRawFrameBuffer.Length - shift];
            Array.Copy(
                pBytesRawFrameBuffer,
                Convert.ToInt32(shift),
                newArray,
                0,
                newArray.Length
                );

            pBytesRawFrameBuffer = newArray;
        }

        private VPN_CONTROL GetAndHandleControlByte(VpnChannel channel, byte[] pBytesRawFrameBuffer)
        {
            //
            // Try to apply v4 header to fetch the packet version info.
            //
            PacketUtils.FULL_HEADER_V4 fullHeader = PacketUtils.PinV4FullHeader(pBytesRawFrameBuffer);

            int controlCode = Convert.ToInt32(fullHeader.ControlHeader.controlValue);

            VPN_CONTROL code;

            if (Enum.IsDefined(typeof(VPN_CONTROL), controlCode))
            {
                code = (VPN_CONTROL)controlCode;
            }
            else
            {
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Received invalid control code");
                return VPN_CONTROL.VPN_CONTROL_INVALID;
            }

            switch (code)
            {
                case VPN_CONTROL.VPN_CONTROL_PACKET:
                    break;
                case VPN_CONTROL.VPN_CONTROL_DISCONNECT:
                    //Unfortunately we can't just call the disconnect method, otherwise the server will instantly reconnect. We need to instead disconnect the profile

                    VpnManagementAgent agent = new VpnManagementAgent();

                    IReadOnlyList<IVpnProfile> profiles = Task.Run(async () => await agent.GetProfilesAsync()).Result;

                    foreach (IVpnProfile profile in profiles)
                    {
                        if (profile is VpnPlugInProfile)
                        {
                            VpnPlugInProfile prof = (VpnPlugInProfile)profile;

                            //We find the associated profile by seeing if it is connected and if its family-name matches 
                            if (prof.ConnectionStatus == VpnManagementConnectionStatus.Connected &&
                                 prof.VpnPluginPackageFamilyName.Equals(Package.Current.Id.FamilyName))
                            {
                                Task.Run(async () => await agent.DisconnectProfileAsync(prof));
                                break;
                            }
                        }
                    }
                    break;
                case VPN_CONTROL.VPN_CONTROL_KEEP_ALIVE:
                    break;
            }

            return code;
        }
        #endregion

        #endregion

        #region Authentication
        internal void AttemptAuthentication(VpnChannel channel, CustomConfiguration config)
        {
            foreach (VPN_AUTHENTICATION auth in config.authentications)
            {
                bool authSuccess = false;
                bool isRetry = false;
                int maxRetries = 3;

                string actualOldUser;
                string actualOldPass;
                string actualUser;
                string actualPass;
                string actualPin;

                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, String.Format("Starting authentication ({0})", auth.authType.ToString()));

                // We will retry up to 'maxRetries' times if there is an authentication failure
                for (int x = 0; x < maxRetries; x++)
                {
                    // If this is a cert-based authentication, then we need to locate a certificate to use
                    if (auth.authType == VpnCredentialType.SmartCard)
                    {
                        if (!GetCertificateForAuth(channel, auth.certSubject, true, out config.authCert))
                        {
                            LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Failed to locate a SmartCard certificate to use for authentication.");
                            break;
                        }
                    }
                    else if (auth.authType == VpnCredentialType.ProtectedCertificate ||
                                auth.authType == VpnCredentialType.UnProtectedCertificate)
                    {
                        if (!GetCertificateForAuth(channel, auth.certSubject, false, out config.authCert))
                        {
                            LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Failed to locate a Protected certificate to use for authentication.");
                            break;
                        }
                    }

                    LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, String.Format("Prompting for credentials (attempt {0} of {1})", (x + 1), maxRetries));

                    // Prompt for credentials
                    VpnPickedCredential pickedCreds;

                    try
                    {
                        pickedCreds = channel.RequestCredentials(auth.authType, isRetry, auth.useSingleSignOn, config.authCert);
                    }
                    catch (Exception ex)
                    {
                        // An exception from the cert-based auths is our only indication of failure to authenticate/consent
                        if (auth.authType == VpnCredentialType.SmartCard ||
                            auth.authType == VpnCredentialType.ProtectedCertificate ||
                            auth.authType == VpnCredentialType.UnProtectedCertificate)
                        {
                            LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, String.Format("Failed to authenticate (exception caught during cert-based auth): {0}", ex.ToString()));
                            continue;
                        }

                        // If this is not a cert based auth, then we re-throw as this exception is unexpected
                        throw;
                    }

                    // Verify the user provided credentials
                    LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Verifying credentials.");

                    //
                    // If this is a cert based auth and we didn't catch any exception earlier, then we are good
                    // (as there will be no creds returned to verify) but we should test to make sure that the cert can
                    // be used to sign data
                    //
                    if (auth.authType == VpnCredentialType.SmartCard ||
                        auth.authType == VpnCredentialType.ProtectedCertificate ||
                        auth.authType == VpnCredentialType.UnProtectedCertificate)
                    {
                        authSuccess = SignDataUsingCert(channel, config.authCert);
                        break;
                    }

                    if (pickedCreds.PasskeyCredential == null)
                    {
                        // Not enough credentials to verify
                        LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Credentials were not provided.");
                        continue;
                    }

                    switch (auth.authType)
                    {
                        case VpnCredentialType.UsernamePassword:

                            if (String.IsNullOrEmpty(pickedCreds.PasskeyCredential.UserName) ||
                                String.IsNullOrEmpty(pickedCreds.PasskeyCredential.Password))
                            {
                                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Username or password was not entered.");
                                break;
                            }

                            actualUser = pickedCreds.PasskeyCredential.UserName;
                            actualPass = pickedCreds.PasskeyCredential.Password;

                            LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, String.Format("Received Username: {0}", actualUser));
                            LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, String.Format("Received Password: {0}", actualPass));

                            if ((!actualUser.Equals(auth.expectedUser, StringComparison.OrdinalIgnoreCase)) ||
                                (!actualPass.Equals(auth.expectedPass)))
                            {
                                // Credentials did not match
                                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Failed authentication.");
                                isRetry = true;
                            }
                            else
                            {
                                // Credentials matched
                                authSuccess = true;
                            }
                            break;

                        case VpnCredentialType.UsernamePasswordChange:

                            if (String.IsNullOrEmpty(pickedCreds.PasskeyCredential.UserName) ||
                                String.IsNullOrEmpty(pickedCreds.PasskeyCredential.Password) ||
                                String.IsNullOrEmpty(pickedCreds.OldPasswordCredential.UserName) ||
                                String.IsNullOrEmpty(pickedCreds.OldPasswordCredential.Password))
                            {
                                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Username or password was not entered.");
                                break;
                            }

                            actualOldUser = pickedCreds.OldPasswordCredential.UserName;
                            actualOldPass = pickedCreds.OldPasswordCredential.Password;
                            actualUser = pickedCreds.PasskeyCredential.UserName;
                            actualPass = pickedCreds.PasskeyCredential.Password;

                            LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, String.Format("Received Old Username: {0}", actualOldUser));
                            LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, String.Format("Received Old Password: {0}", actualOldPass));
                            LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, String.Format("Received Username: {0}", actualUser));
                            LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, String.Format("Received Password: {0}", actualPass));

                            // Check if the username is correct for both old and new credentials
                            if ((!actualOldUser.Equals(auth.expectedUser, StringComparison.OrdinalIgnoreCase)) ||
                                (!actualUser.Equals(auth.expectedUser, StringComparison.OrdinalIgnoreCase)))
                            {
                                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Failed password change (Username is incorrect).");
                                isRetry = true;

                                break;
                            }

                            // Check if the old password was provided correctly
                            if (!actualOldPass.Equals(auth.expectedPass))
                            {
                                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Failed password change (Old password is incorrect).");
                                isRetry = true;

                                break;
                            }

                            // Check if the new password was provided with the expected value
                            if (!actualPass.Equals(auth.expectedNewPass))
                            {
                                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Failed password change (New password is not as expected).");
                                isRetry = true;

                                break;
                            }
                            else
                            {
                                // All credentials matched if we reach this point
                                authSuccess = true;
                            }

                            break;

                        case VpnCredentialType.UsernameOtpPin:

                            if (String.IsNullOrEmpty(pickedCreds.PasskeyCredential.UserName) ||
                                String.IsNullOrEmpty(pickedCreds.PasskeyCredential.Password))
                            {
                                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Username or pin was not entered.");
                                break;
                            }

                            actualUser = pickedCreds.PasskeyCredential.UserName;
                            actualPass = pickedCreds.PasskeyCredential.Password;

                            LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, String.Format("Received Username: {0}", actualUser));
                            LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, String.Format("Received Pin: {0}", actualPass));

                            if ((!actualUser.Equals(auth.expectedUser, StringComparison.OrdinalIgnoreCase)) ||
                                (!actualPass.Equals(auth.expectedPin)))
                            {
                                // Credentials did not match
                                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Failed authentication.");
                                isRetry = true;
                            }
                            else
                            {
                                // Credentials matched
                                authSuccess = true;
                            }

                            break;

                        case VpnCredentialType.UsernamePasswordAndPin:

                            if (String.IsNullOrEmpty(pickedCreds.PasskeyCredential.UserName) ||
                                String.IsNullOrEmpty(pickedCreds.PasskeyCredential.Password) ||
                                String.IsNullOrEmpty(pickedCreds.AdditionalPin))
                            {
                                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Username, password, or pin were not entered.");
                                break;
                            }

                            actualUser = pickedCreds.PasskeyCredential.UserName;
                            actualPass = pickedCreds.PasskeyCredential.Password;
                            actualPin = pickedCreds.AdditionalPin;

                            LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, String.Format("Received Username: {0}", actualUser));
                            LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, String.Format("Received Password: {0}", actualPass));
                            LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, String.Format("Received Pin: {0}", actualPin));

                            if ((!actualUser.Equals(auth.expectedUser, StringComparison.OrdinalIgnoreCase)) ||
                                (!actualPass.Equals(auth.expectedPass)) ||
                                (!actualPin.Equals(auth.expectedPin)))
                            {
                                // Credentials did not match
                                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Failed authentication.");
                                isRetry = true;
                            }
                            else
                            {
                                // Credentials matched
                                authSuccess = true;
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
                    LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Error: Authentication has failed.");
                    throw new System.UnauthorizedAccessException("Authentication has failed.");
                }

                //
                // If we reached here, then this authentication was successful. We will now either move on to connecting our socket
                // or loop back around for the next authentication method (in the case where multiple auths were specified)
                //
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, String.Format("Successful authentication ({0})", auth.authType.ToString()));
            }
        }
        /// <summary>
        /// Retrieves a certificate to use for authentication
        /// </summary>
        /// <param name="channel">VpnChannel</param>
        /// <param name="subject">Subject of the cert to pick</param>
        /// <param name="onlySmartCardCert">Select only smart card certs</param>
        /// <param name="theCert">Certificate to return</param>
        /// <returns>bool</returns>
        private bool GetCertificateForAuth(VpnChannel channel, string subject, bool onlySmartCardCert, out Certificate theCert)
        {
            bool retVal = false;
            CertificateQuery certQuery = new CertificateQuery();
            theCert = null;

            LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, "Querying for certificates...");

            if (onlySmartCardCert)
            {
                //
                // We use a certificate query to locate a certificate in the user store which is a hardware certificate and has the
                // "Smart Card Log-on" EKU.
                //
                certQuery.HardwareOnly = true;
                certQuery.EnhancedKeyUsages.Add("1.3.6.1.4.1.311.20.2.2");
            }
            else
            {
                certQuery.HardwareOnly = false;
            }

            try
            {
                Task<IReadOnlyList<Certificate>> t = CertificateStores.FindAllAsync(certQuery).AsTask<IReadOnlyList<Certificate>>();
                t.Wait();

                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, String.Format("Found {0} matching certificates...", t.Result.Count.ToString()));

                foreach (Certificate cert in t.Result)
                {
                    string certDetails = "Certificate details:\n";
                    certDetails += String.Format("Subject: {0}\n", cert.Subject);
                    certDetails += String.Format("Issuer: {0}\n", cert.Issuer);
                    certDetails += String.Format("Private Key: {0}\n", cert.HasPrivateKey.ToString());

                    foreach (string eku in cert.EnhancedKeyUsages)
                    {
                        certDetails += String.Format("EKU: {0}\n", eku);
                    }

                    LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, certDetails);

                    //
                    // In the absence of any better logic currently, we will return the first matching cert that we find.
                    //
                    // Also, we should check for cert->IsStronglyProtected = True in the case of smartcard - but this property is currently
                    // failing
                    //
                    if (!String.IsNullOrEmpty(subject))
                    {
                        LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, String.Format("Checking to see if this cert matches desired subject: {0}", subject));

                        // The caller requested a specific subject to be matched, so we need to check if this cert is a match
                        if (!cert.Subject.Equals(subject, StringComparison.OrdinalIgnoreCase))
                        {
                            // No match, move to next cert
                            LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, "Cert failed to match desired subject.");
                            continue;
                        }
                    }

                    LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, "Match found! Returning this cert.");

                    theCert = cert;
                    retVal = true;

                    break;
                }
            }
            catch (Exception ex)
            {
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, String.Format("Exception caught during GetCertificateForAuth: {0}.", ex.ToString()));
            }

            return retVal;
        }

        /// <summary>
        /// Use a Certificate to sign some test data and verify that the signing was successful
        /// </summary>
        /// <param name="channel">VpnChannel</param>
        /// <param name="theCert">Certificate to use for the signing</param>
        /// <returns>bool</returns>
        bool SignDataUsingCert(VpnChannel channel, Certificate theCert)
        {
            CryptographicKey keyPair;
            IBuffer dataBlob;
            IBuffer signature;
            String cookie;

            // Ensure that the cert has a private key
            if (!theCert.HasPrivateKey)
            {
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, "Unable to sign. Certificate has no private key available.");
                return false;
            }

            // 
            // Obtain the key pair for this certificate
            //
            LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, "Obtaining key pair from certificate.");

            try
            {
                Task<CryptographicKey> t = PersistedKeyProvider.OpenKeyPairFromCertificateAsync(theCert, HashAlgorithmNames.Sha1, CryptographicPadding.RsaPkcs1V15).AsTask<CryptographicKey>();
                t.Wait();

                keyPair = t.Result;
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, String.Format("Obtained key pair. Key size: {0}", keyPair.KeySize.ToString()));
            }
            catch (Exception ex)
            {
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, String.Format("Exception caught during OpenKeyPairFromCertificateAsync: {0}", ex.ToString()));
                return false;
            }

            //
            // Use the key pair to sign some test data
            //

            cookie = "Some Data to sign";
            dataBlob = CryptographicBuffer.ConvertStringToBinary(cookie, BinaryStringEncoding.Utf16BE);

            LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, "Attempting to sign a test data blob.");

            try
            {
                Task<IBuffer> t = CryptographicEngine.SignAsync(keyPair, dataBlob).AsTask<IBuffer>();
                t.Wait();

                signature = t.Result;
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, "Signing complete.");
            }
            catch (Exception ex)
            {
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, String.Format("Exception caught during SignAsync: {0}", ex.ToString()));
                return false;
            }

            //
            // Verify the signed data to ensure that signing was really successful
            //
            LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, "Verifying signature.");

            try
            {
                if (!CryptographicEngine.VerifySignature(keyPair, dataBlob, signature))
                {
                    LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Verify signature Failed.");
                    return false;
                }

                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM, "Successfully signed and verified signature.");
            }
            catch (Exception ex)
            {
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, String.Format("Exception caught during VerifySignature: {0}", ex.ToString()));
                return false;
            }

            return true;
        }
        #endregion

        #region Private Helper Methods


        /// <summary>
        /// Logging function which can selectively log based on the loglevel which was requested via 
        /// the VPN profile custom configuration
        /// </summary>
        /// <param name="channel">VpnChannel object providing access to LogDiagnosticMessage</param>
        /// <param name="level">The log level requested for this message</param>
        /// <param name="message">Message to log</param>
        private void LogMessage(VpnChannel channel, VPN_PLUGIN_LOG_LEVEL level, string message)
        {
            logger.LogMessage(channel, level, message);
        }

        /// <summary>
        /// Simple way to check various API methods that were added in Windows 11/backported to windows 10 in 9C
        /// to verify that they exist in windows.
        /// 
        /// If they don't exist, we cause the app to fail to connect.
        /// 
        /// A more complex implementation could use these checks in order to make different "versions" of the app run depending on what APIs are available
        /// </summary>
        /// <param name="channel">VpnChannel object providing access to LogDiagnosticMessage</param>
        private bool CheckAPIsExist(VpnChannel channel)
        {
            bool apiExist = true;
            if(!Windows.Foundation.Metadata.ApiInformation.IsMethodPresent("Windows.Networking.Vpn.VpnChannel", "ActivateForeground", 2))
            {
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "ActivateForeground method not present.");
                apiExist = false;
            }

            if(!Windows.Foundation.Metadata.ApiInformation.IsMethodPresent("Windows.Networking.Vpn.VpnChannel", "AppendVpnSendPacketBuffer", 1))
            {
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "AppendVpnSendPacketBuffer method not present.");
                apiExist = false;
            }

            if(!Windows.Foundation.Metadata.ApiInformation.IsMethodPresent("Windows.Networking.Vpn.VpnChannel", "FlushVpnSendPacketBuffers", 0))
            {
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "FlushVpnSendPacketBuffers method not present.");
                apiExist = false;
            }

            if(!Windows.Foundation.Metadata.ApiInformation.IsMethodPresent("Windows.Networking.Vpn.VpnChannel", "AppendVpnReceivePacketBuffer", 1))
            {
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "AppendVpnReceivePacketBuffer method not present.");
                apiExist = false;
            }

            if(!Windows.Foundation.Metadata.ApiInformation.IsMethodPresent("Windows.Networking.Vpn.VpnChannel", "FlushVpnReceivePacketBuffers", 0))
            {
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "FlushVpnReceivePacketBuffers method not present.");
                apiExist = false;
            }

            return apiExist;
        }

        private static void Split<T>(T[] source, int index, out T[] first, out T[] last)
        {
            int len2 = source.Length - index;
            first = new T[index];
            last = new T[len2];
            Array.Copy(source, 0, first, 0, index);
            Array.Copy(source, index, last, 0, len2);
        }

        /// <summary>
        /// Logs the properties of all UI elements within a list of IVpnCustomPrompt's
        /// </summary>
        /// <param name="channel">VpnChannel</param>
        /// <param name="customPrompt">List of IVpnCustomPrompt</param>
        private void LogCustomPrompt(VpnChannel channel, IReadOnlyList<IVpnCustomPrompt> customPrompt)
        {
            //
            // Look through the UI elements in the prompt and output their properties for debugging/verification.
            // If the prompt has already been displayed to the user then this will include any values which were
            // set/selected by the user before they clicked 'Next' in the VAN UI.
            //
            foreach (IVpnCustomPrompt element in customPrompt)
            {
                string elementOutput;

                // Output the type of this UI element
                elementOutput = String.Format("Element Type: {0}\n", element.GetType().FullName);

                // Output the properties which are global to all UI elements (this covers all of the properties for VpnCustomErrorBox)
                elementOutput += String.Format("Label: {0}\n", element.Label);
                elementOutput += String.Format("Compulsory: {0}\n", element.Compulsory.ToString());
                elementOutput += String.Format("Bordered: {0}\n", element.Bordered.ToString());

                // Output any unique properties of the UI element based on its type
                switch (element.GetType().FullName)
                {
                    case "Windows.Networking.Vpn.VpnCustomEditBox":

                        elementOutput += String.Format("DefaultText: {0}\n", ((VpnCustomEditBox)element).DefaultText);
                        elementOutput += String.Format("NoEcho: {0}\n", ((VpnCustomEditBox)element).NoEcho.ToString());
                        elementOutput += String.Format("Text: {0}\n", ((VpnCustomEditBox)element).Text);

                        break;

                    case "Windows.Networking.Vpn.VpnCustomComboBox":

                        foreach (string option in ((VpnCustomComboBox)element).OptionsText)
                        {
                            elementOutput += String.Format("Option: {0}\n", option);
                        }

                        elementOutput += String.Format("Selected: {0}\n", ((VpnCustomComboBox)element).Selected.ToString());

                        break;

                    case "Windows.Networking.Vpn.VpnCustomTextBox":

                        elementOutput += String.Format("DisplayText: {0}\n", ((VpnCustomTextBox)element).DisplayText);

                        break;

                    case "Windows.Networking.Vpn.VpnCustomCheckBox":

                        elementOutput += String.Format("InitialCheckState: {0}\n", ((VpnCustomCheckBox)element).InitialCheckState.ToString());
                        elementOutput += String.Format("Checked: {0}\n", ((VpnCustomCheckBox)element).Checked.ToString());

                        break;
                }

                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, elementOutput);
            }
        }

        /// <summary>
        /// Logs a string representation of a packet for debugging
        /// </summary>
        /// <param name="channel">VpnChannel</param>
        /// <param name="isInbound">bool</param>
        /// <param name="spBuffer">VpnPacketBuffer</param>
        private void LogPacket(VpnChannel channel, bool isInbound, VpnPacketBuffer spBuffer)
        {
            uint length = 0;
            Windows.Storage.Streams.Buffer spPacketBuffer;
            byte[] pBytesRawPacketBuffer = null;
            string strPacket = "";

            if (spBuffer == null || spBuffer.Buffer == null)
            {
                return;
            }

            // Get the raw packet buffer
            spPacketBuffer = spBuffer.Buffer;
            length = spPacketBuffer.Length;

            pBytesRawPacketBuffer = new byte[length];
            pBytesRawPacketBuffer = VpnPluginGetRawByteBuffer(spPacketBuffer);

            // Apply packet header structure to the buffer bytes
            PacketUtils.FULL_HEADER_V4 fullHeader = PacketUtils.PinV4FullHeader(pBytesRawPacketBuffer);

            // Now we can see what type of packet this is and output it accordingly
            strPacket = (isInbound ? "Decapsulating Packet" : "Encapsulating Packet");

            strPacket += ":: Control= " + fullHeader.ControlHeader.controlValue;

            // Check IP packet version
            if (fullHeader.IpHeader.Version == 4)
            {
                // This is a IPv4 packet
                strPacket += " :: Version=4";

                // Source and Destination
                strPacket += " :: Src=" + fullHeader.IpHeader.SourceAddress;
                strPacket += " :: Dst=" + fullHeader.IpHeader.DestinationAddress;

                // Determine protocol and output packet header accordingly
                switch (fullHeader.IpHeader.Protocol)
                {
                    case 1: // icmpv4

                        strPacket += " :: Protocol=icmpv4";
                        strPacket += " :: Type=" + fullHeader.IpProtocolHeader.IcmpV4Header.Type.ToString();
                        strPacket += " :: Code=" + fullHeader.IpProtocolHeader.IcmpV4Header.Code.ToString();
                        break;

                    case 6: // tcp

                        strPacket += " :: Protocol=tcp";
                        strPacket += " :: SrcPort=" + PacketUtils.ReverseByteOrder(fullHeader.IpProtocolHeader.TcpHeader.SourcePort).ToString();
                        strPacket += " :: DstPort=" + PacketUtils.ReverseByteOrder(fullHeader.IpProtocolHeader.TcpHeader.DestinationPort).ToString();
                        break;
                    case 17: // udp

                        strPacket += " :: Protocol=udp";
                        strPacket += " :: SrcPort=" + PacketUtils.ReverseByteOrder(fullHeader.IpProtocolHeader.UdpHeader.SourcePort).ToString();
                        strPacket += " :: DstPort=" + PacketUtils.ReverseByteOrder(fullHeader.IpProtocolHeader.UdpHeader.DestinationPort).ToString();
                        break;

                    default: // unhandled protocol

                        strPacket += " :: Protocol=" + fullHeader.IpHeader.Protocol.ToString();
                        break;
                }

                strPacket += " :: Length=" + PacketUtils.ReverseByteOrder(fullHeader.IpHeader.TotalLengthBytes).ToString();
            }
            else if (fullHeader.IpHeader.Version == 6)
            {
                // Apply V6 packet header structure to the buffer bytes
                PacketUtils.FULL_HEADER_V6 fullHeaderV6 = PacketUtils.PinV6FullHeader(pBytesRawPacketBuffer);

                // This is a IPv6 packet
                strPacket += " :: Version=6";

                // Source and Destination
                strPacket += " :: Src=" + fullHeaderV6.IpHeader.SourceAddress;
                strPacket += " :: Dst=" + fullHeaderV6.IpHeader.DestinationAddress;

                // Determine protocol and output packet header accordingly
                switch (fullHeaderV6.IpHeader.NextHeader)
                {
                    case 2: // igmp

                        strPacket += " :: Protocol=igmp";
                        break;

                    case 58: // icmp over ipv6

                        strPacket += " :: Protocol=icmpv6";
                        strPacket += " :: Type=" + fullHeaderV6.IpProtocolHeader.IcmpV6Header.Type.ToString();
                        strPacket += " :: Code=" + fullHeaderV6.IpProtocolHeader.IcmpV6Header.Code.ToString();
                        break;

                    case 6: // tcp

                        strPacket += " :: Protocol=tcp";
                        strPacket += " :: SrcPort=" + PacketUtils.ReverseByteOrder(fullHeaderV6.IpProtocolHeader.TcpHeader.SourcePort).ToString();
                        strPacket += " :: DstPort=" + PacketUtils.ReverseByteOrder(fullHeaderV6.IpProtocolHeader.TcpHeader.DestinationPort).ToString();
                        break;

                    case 17: // udp

                        strPacket += " :: Protocol=udp";
                        strPacket += " :: SrcPort=" + PacketUtils.ReverseByteOrder(fullHeaderV6.IpProtocolHeader.UdpHeader.SourcePort).ToString();
                        strPacket += " :: DstPort=" + PacketUtils.ReverseByteOrder(fullHeaderV6.IpProtocolHeader.UdpHeader.DestinationPort).ToString();
                        break;

                    default: // unhandled protocol

                        strPacket += " :: Protocol=" + fullHeaderV6.IpHeader.NextHeader.ToString();
                        break;
                }

                strPacket += " :: Length=" + (PacketUtils.ReverseByteOrder(fullHeaderV6.IpHeader.PayloadLength) + IPV6_HEADER_LENGTH).ToString();
            }
            else
            {
                // This is not a IPv4 packet, so it is not supported at the moment
                strPacket += " :: Version=" + fullHeader.IpHeader.Version.ToString() + " :: WARNING - Non-IPv4 packet received";
            }
            LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, strPacket);
        }

        /// <summary>
        /// Convert a Buffer into a string of hex values for friendly logging of the buffer's content
        /// </summary>
        /// <param name="blob">Windows.Storage.Streams.Buffer</param>
        /// <returns>string</returns>
        private string ConvertBufferToHexString(Windows.Storage.Streams.Buffer blob)
        {
            string retVal = String.Empty;

            if (blob != null)
            {
                // Convert blob to a hex string
                string hexString = CryptographicBuffer.EncodeToHexString(blob);

                for (int x = 0; x < (hexString.Length / 2); x++)
                {
                    if ((x % 8) == 0)
                    {
                        retVal += "\n";
                    }

                    retVal += "0x" + hexString[2 * x] + hexString[2 * x + 1] + " ";
                }
            }

            return retVal;
        }

        /// <summary>
        /// Retrieves a byte array representing the passed in Buffer
        /// </summary>
        /// <param name="buffer">Streams.Buffer</param>
        /// <returns>Byte array</returns>
        private byte[] VpnPluginGetRawByteBuffer(Windows.Storage.Streams.Buffer buffer)
        {
            if (buffer == null)
            {
                return new byte[0];
            }

            if (buffer.Length == 0)
            {
                return new byte[buffer.Capacity];
            }

            return WindowsRuntimeBufferExtensions.ToArray(buffer);
        }

        /// <summary>
        /// Writes a byte array to the same memory referenced by the passed in Buffer
        /// </summary>
        /// <param name="source">ref Byte array</param>
        /// <param name="sourceIndex">int</param>
        /// <param name="destination">ref Streams.Buffer</param>
        /// <param name="destinationIndex">int</param>
        /// <param name="length">int</param>
        private void BufferCopy(ref byte[] source, int sourceIndex, ref Windows.Storage.Streams.Buffer destination, int destinationIndex, int length)
        {
            if (source.Length == 0 ||
                sourceIndex > source.Length ||
                (sourceIndex + length) > source.Length)
            {
                return;
            }

            System.IO.Stream dstStream = destination.AsStream();
            dstStream.Seek(destinationIndex, System.IO.SeekOrigin.Begin);

            for (int i = sourceIndex; i < (sourceIndex + length); ++i)
            {
                dstStream.WriteByte(source[i]);
            }
        }

        /// <summary>
        /// Logs a string representation of a Buffer
        /// </summary>
        /// <param name="channel">VpnChannel</param>
        /// <param name="identifier">string</param>
        /// <param name="buff">Windows.Storage.Streams.Buffer</param>
        private void LogPacketBuffer(VpnChannel channel, string identifier, Windows.Storage.Streams.Buffer buff)
        {
            if (buff == null)
            {
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, String.Format("Warning: Unable to log a null buffer for {0}.", identifier));
                return;
            }

            LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, String.Format("Buffer dump for '{0}':\n{1}", identifier, ConvertBufferToHexString(buff)));
        }

        /// <summary>
        /// Determine whether a raw framebuffer contains a v4 or v6 packet (assuming that the raw buffer starts with a new packet
        /// with at least 1 byte of header present)
        /// </summary>
        /// <param name="channel">VpnChannel</param>
        /// <param name="pBytesRawFrameBuffer">byte[]</param>
        /// <returns>bool</returns>
        private bool IsV6Packet(VpnChannel channel, byte[] pBytesRawFrameBuffer)
        {
            //
            // Try to apply v4 header to fetch the packet version info.
            //
            PacketUtils.FULL_HEADER_V4 v4Header = PacketUtils.PinV4FullHeader(pBytesRawFrameBuffer);

            if (v4Header.IpHeader.Version != 4 && v4Header.IpHeader.Version != 6)
            {
                LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, String.Format("ERROR: Non-IPv4/IPv6 packet received, Version={0}", v4Header.IpHeader.Version.ToString()));
                throw new NullReferenceException("ERROR: Received a non-ipv4/ipv6 packet, packet version unknown.");
            }

            return (v4Header.IpHeader.Version == 6);
        }

        private void updateSharedMemory()
        {
            int size = Marshal.SizeOf(this.packetCounter);

            //Transform packetCounter to byte array

            byte[] counterBytes = new byte[size];

            IntPtr ptr = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(this.packetCounter, ptr, true);
            Marshal.Copy(ptr, counterBytes, 0, size);
            Marshal.FreeHGlobal(ptr);

            MemoryMappedFile packetCountMemory = MemoryMappedFile.CreateOrOpen(mappedMemoryName, size);

            //Warning: There is an inherent race condition here, technically the client could read this info as it is getting written to
            //This is just being used for debugging purposes so this is not super critical. Synchronization code would be necessary to fix.
            using (MemoryMappedViewAccessor accessor = packetCountMemory.CreateViewAccessor())
            {
                accessor.WriteArray(0, counterBytes, 0, size);
            }
        }

        #endregion
    }
}
