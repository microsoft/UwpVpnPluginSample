using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace SimpleVpnServer
{
    /// <summary>
    /// Fake VPN server implementation
    /// </summary>
    internal class Server
    {
        #region Private members

        private TcpListener tcpListener;
        private TcpListener tcpListenerv6;
        private UdpClient udpListener;
        private UdpClient udpListenerv6;

        private Thread tcpListenThread;

        private IPEndPoint udpEndPoint;
        private IPEndPoint udpEndPointv6;

        private volatile bool isTcpStarted = false;
        private volatile bool isUdpStarted = false;

        private volatile Dictionary<EndPoint, Client> clientDictionary;

        //used to map where a response from a server needs to go back on client machine
        private volatile Dictionary<EndPoint, AddressBytes> originalSourceDictionary;
        private EndPoint mainClient;

        internal PACKET_COUNTER packetCounter = new PACKET_COUNTER();

        #endregion

        #region Structs

        internal struct UdpState
        {
            internal UdpClient Client;
            internal IPEndPoint EndPoint;
        }

        internal struct AddressBytes
        {
            internal uint address;
            internal ushort port;
        }
        #endregion

        #region Constructor

        /// <summary>
        /// Constructor
        /// </summary>
        internal Server()
        {
            clientDictionary = new Dictionary<EndPoint, Client>();
            originalSourceDictionary = new Dictionary<EndPoint, AddressBytes>();
        }

        #endregion

        #region Internal methods

        /// <summary>
        /// Starts the server and listens for inbound TCP connections from clients
        /// </summary>
        /// <returns>bool</returns>
        internal bool StartServer(int serverPort)
        {
            if (!isTcpStarted && !isUdpStarted)
            {
                try
                {
                    Logger.LogMessage(
                        "Server is starting on port {0} ...\n",
                        serverPort.ToString(CultureInfo.CurrentCulture)
                        );

                    if (SimpleVpnServer.Forward)
                    {
                        Logger.LogMessage("UDP packet forwarding is enabled.");
                    }

                    // Start the UDP server listener (if required)

                    if (SimpleVpnServer.AcceptUdp)
                    {
                        udpEndPoint = new IPEndPoint(IPAddress.Any, serverPort);
                        udpEndPointv6 = new IPEndPoint(IPAddress.IPv6Any, serverPort);

                        udpListener = new UdpClient(serverPort, AddressFamily.InterNetwork);
                        udpListenerv6 = new UdpClient(serverPort, AddressFamily.InterNetworkV6);

                        UdpState state = new UdpState()
                        {
                            Client = udpListener,
                            EndPoint = udpEndPoint
                        };

                        UdpState statev6 = new UdpState()
                        {
                            Client = udpListenerv6,
                            EndPoint = udpEndPointv6
                        };

                        udpListener.BeginReceive(new AsyncCallback(UdpReceiveCallback), state);
                        udpListenerv6.BeginReceive(new AsyncCallback(UdpReceiveCallback), statev6);

                        Logger.LogMessage("Server is listening for UDP connections.");
                        isUdpStarted = true;
                    }
                    // Start the TCP server listener thread (if required)

                    if (SimpleVpnServer.AcceptTcp)
                    {
                        this.tcpListener = new TcpListener(IPAddress.Any, serverPort);
                        this.tcpListenerv6 = new TcpListener(IPAddress.IPv6Any, serverPort);

                        this.tcpListenThread = new Thread(new ThreadStart(ListenForTCPClients));
                        this.tcpListenThread.Start();

                        // Poll for TCP server to finish starting up

                        for (int x = 0; x < 5; x++)
                        {
                            if (isTcpStarted)
                                break;

                            Thread.Sleep(1000);
                        }

                        if (isTcpStarted)
                            return true;

                        // Failure

                        Logger.LogError("TCP Server failed to start.");
                        return false;
                    }

                    return true;
                }
                catch (System.Exception ex)
                {
                    Logger.LogError("Exception caught while starting server: {0}", ex.ToString());
                    return false;
                }
            }

            Logger.LogMessage("Warning: StartServer called while server was already running.");
            return true;
        }

        /// <summary>
        /// Stops the server
        /// </summary>
        /// <returns>bool</returns>
        internal bool StopServer()
        {
            if (isTcpStarted || isUdpStarted)
            {
                try
                {
                    //attempt to disconnect
                    Disconnect();

                    Logger.LogMessage("Server is stopping ...");

                    // Stop the server

                    if (isTcpStarted)
                    {
                        tcpListener.Stop();
                        tcpListenerv6.Stop();
                    }

                    if (isUdpStarted)
                    {
                        udpListener.Close();
                        udpListenerv6.Close();
                    }

                    // Signal listener threads to terminate

                    isTcpStarted = false;
                    isUdpStarted = false;

                    Thread.Sleep(1500);

                    Logger.LogMessage("Server is stopped.");
                }
                catch (System.Exception ex)
                {
                    Logger.LogError("Exception caught while stopping Server: {0}", ex.ToString());
                    return false;
                }
            }

            return true;
        }

        internal void Disconnect()
        {
            if (mainClient == null)
            {
                Console.WriteLine("Not connected so cannot disconnect");
                return;
            }
            byte[] dataOut = new byte[1];

            dataOut[0] = (byte) VPN_CONTROL.VPN_CONTROL_DISCONNECT;
            Client mainOne;
            lock (clientDictionary)
            {
                if (clientDictionary.TryGetValue(mainClient, out mainOne))
                {
                    mainOne.Send(dataOut, dataOut.Length);

                    if (SimpleVpnServer.OutputData)
                    {
                        mainOne.LogMessage(
                            Logger.MessageType.Received,
                            "Sending disconnect message to client"
                            );
                    }
                    mainClient = null;
                }
                else
                {
                    Console.WriteLine("main client not found?");
                }
            }
        }

        internal bool isConnected()
        {
            return (mainClient != null);
        }
        #endregion

        #region Private methods

        /// <summary>
        /// This method listens for pending TCP client connections in a loop. It is started as a worker thread 
        /// when StartServer is called.
        /// </summary>
        /// <returns></returns>
        private void ListenForTCPClients()
        {
            try
            {
                // Start the TCP Listener

                tcpListener.Start();
                tcpListenerv6.Start();
                isTcpStarted = true;

                Logger.LogMessage("Server is listening for TCP connections.");

                while (true)
                {
                    if (!isTcpStarted)
                    {
                        // Server is stopped or stopping, terminate thread
                        return;
                    }

                    // Do we have a pending client connection request?
                    if (!this.tcpListener.Pending() && !this.tcpListenerv6.Pending())
                    {
                        // No pending clients, skip to the next iteration of the loop

                        Thread.Sleep(1000);
                        continue;
                    }

                    // Accept the TCP client connection
                    //
                    if (this.tcpListener.Pending())
                    {
                        tcpListener.BeginAcceptTcpClient(new AsyncCallback(OnTcpAccept), tcpListener);
                    }
                    else
                    {
                        tcpListenerv6.BeginAcceptTcpClient(new AsyncCallback(OnTcpAccept), tcpListenerv6);
                    }
                }
            }
            catch (System.Exception ex)
            {
                Logger.LogError("Error encountered during ListenForTCPClients: {0}\n", ex.ToString());
            }
        }

        /// <summary>
        /// UDP receive callback (new data arrived from a UDP client)
        /// </summary>
        /// <param name="ar"></param>
        private void UdpReceiveCallback(IAsyncResult ar)
        {
            try
            {
                Client client;
                IPEndPoint endPoint;

                byte[] read;

                UdpState state = (UdpState)ar.AsyncState;
                UdpClient udpClient = state.Client;

                if (udpClient.Client == null)
                {
                    // Server is probably shutting down
                    return;
                }

                try
                {
                    // Read the udp data and obtain the remote endpoint

                    read = udpClient.EndReceive(ar, ref state.EndPoint);
                    endPoint = state.EndPoint;
                }
                catch(SocketException ex)
                {
                    if (ex.SocketErrorCode == SocketError.ConnectionReset)
                    {
                        // This means that the client went away (closed it's socket) so we should handle this

                        if (clientDictionary.TryGetValue(state.EndPoint, out client))
                        {
                            client.StopUdpTimer();

                            client.LogMessage(Logger.MessageType.Disconnect, "UDP Client ({0})", state.EndPoint);

                            if (client.State == Client.ClientState.Dual)
                            {
                                // If we had dual sockets, not we only have TCP

                                client.State = Client.ClientState.TCP;
                            }
                            else
                            {
                                // We only had a UDP socket for this client, so now the client is dead

                                if (mainClient != null && client.EndPoint.Equals(mainClient.ToString()))
                                {
                                    mainClient = null;
                                }

                                lock (clientDictionary)
                                {
                                    clientDictionary.Remove(client.UdpClient.EndPoint);
                                }

                                Logger.UnassignClientColor(client.LoggingColor);
                                client = null;
                            }
                        }

                        // Get ready to receive more data

                        udpClient.BeginReceive(new AsyncCallback(UdpReceiveCallback), state);

                        return;
                    }

                    // This is probably an unexpected issue, re-throw

                    throw;
                }

                lock (clientDictionary)
                {
                    // Check if this is a new or existing UDP client
                    if (clientDictionary.TryGetValue(endPoint, out client))
                    {
                        // This is an existing UDP client, handle the possible states
                        switch (client.State)
                        {
                            case Client.ClientState.Dual:
                            case Client.ClientState.UDP:

                                // Update the client in case there was a socket disconnect inbetween sends and the endpoint port changed,
                                // also this operation will cause the UDP timer to be reset, which will keep the client connected

                                client.UdpClient = state;
                                break;

                            case Client.ClientState.TCP:

                                // We already had a TCP socket for this client, now we can update to dual sockets

                                client.State = Client.ClientState.Dual;
                                client.UdpClient = state;

                                client.LogMessage(Logger.MessageType.FlowEstablish, "UDP Client (dual) ({0})", endPoint.ToString());
                                break;

                            case Client.ClientState.None:

                                // This is probably a previously expired UDP client, bring it back to life

                                client.State = Client.ClientState.UDP;
                                client.UdpClient = state;

                                client.LogMessage(Logger.MessageType.FlowEstablish, "UDP Client ({0})", endPoint.ToString());
                                break;
                        }
                    }
                    else
                    {
                        // This isn't an existing UDP client, add it
                        client = new Client(state);
                        client.LoggingColor = Logger.AssignClientColor();

                        clientDictionary.Add(endPoint, client);

                        client.LogMessage(Logger.MessageType.FlowEstablish, "UDP Client ({0})", endPoint.ToString());
                    }

                    if (SimpleVpnServer.OutputData)
                    {
                        client.LogMessage(
                            Logger.MessageType.Received,
                            "UDP (from {0}): {1} bytes",
                            endPoint.ToString(),
                            read.Length
                            );
                    }

                    HandleReceiveFromClient(client, read, read.Length);
                }
                        
                // Get ready to receive more data
                udpClient.BeginReceive(new AsyncCallback(UdpReceiveCallback), state);
            }
            catch (Exception ex)
            {
                Logger.LogError("Exception caught during UdpReceiveCallback: {0}\n", ex.ToString());
            }
        }

        /// <summary>
        /// OnTcpAccept callback (new TCP client connected)
        /// </summary>
        /// <param name="res">IAsyncResult</param>
        private void OnTcpAccept(IAsyncResult res)
        {
            try
            {
                string clientEndpoint = String.Empty;
                string clientAddress = String.Empty;

                TcpListener listener = (TcpListener)res.AsyncState;
                TcpClient client = listener.EndAcceptTcpClient(res);

                client.ReceiveBufferSize = SimpleVpnServer.BufferSize;
                client.SendBufferSize = SimpleVpnServer.BufferSize;
                client.NoDelay = true;
                clientEndpoint = client.Client.RemoteEndPoint.ToString();

                Byte[] receiveBytes = new byte[client.ReceiveBufferSize];

                // Check if this is a new or existing client
                Client myclient;
                lock (clientDictionary)
                {
                    if (clientDictionary.TryGetValue(client.Client.RemoteEndPoint, out myclient))
                    {
                        // This is an existing client, handle the possible states
                        if (myclient.State == Client.ClientState.UDP)
                        {
                            // We had a UDP socket for this client, now we can update to dual sockets

                            myclient.State = Client.ClientState.Dual;
                            myclient.TcpClient = client;
                            myclient.Buffer = receiveBytes;

                            myclient.LogMessage(Logger.MessageType.Connect, "TCP Client (dual) ({0})", clientEndpoint);
                        }
                        else if (myclient.State == Client.ClientState.None)
                        {
                            // This is probably an expired UDP client, now we just have a TCP socket for them

                            myclient.State = Client.ClientState.TCP;
                            myclient.TcpClient = client;
                            myclient.Buffer = receiveBytes;

                            myclient.LogMessage(Logger.MessageType.Connect, "TCP Client ({0})", clientEndpoint);
                        }
                        else if (myclient.State == Client.ClientState.TCP || myclient.State == Client.ClientState.Dual)
                        {
                            // Interesting case, it seems as though the client is making a second TCP connection to the server, even though we already have an existing connection from them.
                            // This could be a reconnect scenario in which the server has not yet been able to determine that previous TCP client socket died. We don't want to have two
                            // TCP connections from the same client, so the way to handle this is to overwrite the previous connection with the new one.

                            myclient.TcpClient = client;
                            myclient.Buffer = receiveBytes;

                            myclient.LogMessage(Logger.MessageType.Reconnect, "TCP Client ({0})", clientEndpoint);
                        }
                    }
                    else
                    {
                        // This isn't an existing client, add it
                        myclient = new Client(client, receiveBytes);
                        myclient.LoggingColor = Logger.AssignClientColor();

                        clientDictionary.Add(client.Client.RemoteEndPoint, myclient);

                        myclient.LogMessage(Logger.MessageType.Connect, "TCP Client ({0})", clientEndpoint);
                    }

                    mainClient = client.Client.RemoteEndPoint;
                    //reset packetCounter since we've received a new connection
                    packetCounter = new PACKET_COUNTER();
                }
                // Start receiving data from this TCP client

                NetworkStream stream = myclient.NetworkStream;
                if (stream.CanRead)
                {
                    try
                    {
                        stream.BeginRead(myclient.Buffer, 0, myclient.Buffer.Length, new AsyncCallback(TcpReceiveCallback), myclient);
                    }
                    catch (SocketException ex)
                    {
                        // It's strange to hit an exception here, but it does happen depending on timing

                        if (ex.SocketErrorCode == SocketError.ConnectionReset)
                        {
                            // This means that a client went away (closed it's socket) so we need to remove this client

                            myclient.LogMessage(Logger.MessageType.Disconnect, "TCP Client ({0})", clientEndpoint);

                            

                            if (myclient.State == Client.ClientState.Dual)
                            {
                                // If we had dual sockets, not we only have UDP

                                myclient.State = Client.ClientState.UDP;
                            }
                            else
                            {
                                // We only had a TCP socket for this client, so now the client is dead

                                if (mainClient != null && myclient.EndPoint.Equals(mainClient.ToString()))
                                {
                                    mainClient = null;
                                }

                                lock (clientDictionary)
                                {
                                    clientDictionary.Remove(client.Client.RemoteEndPoint);
                                }

                                myclient.TcpClient.Close();
                                Logger.UnassignClientColor(myclient.LoggingColor);

                                myclient = null;
                            }
                        }

                        // This is probably an unexpected issue, re-throw

                        throw;
                    }
                }
                else
                {
                    Logger.LogError("Unable to read from the TCP client NetworkStream.");
                }
            }
            catch (System.Exception ex)
            {
                Logger.LogError("Exception caught during OnTcpAccept: {0}\n", ex.ToString());
            }
        }

        /// <summary>
        /// TCP Receive Callback (new data arrived from a TCP client)
        /// </summary>
        /// <param name="result">IAsyncResult</param>
        private void TcpReceiveCallback(IAsyncResult result)
        {
            Client client = result.AsyncState as Client;
            if (client == null) return;

            try
            {
                // Read data from the socket stream

                NetworkStream stream = client.NetworkStream;
                if (stream == null) return;

                int read = stream.EndRead(result);

                if (SimpleVpnServer.OutputData)
                {
                    client.LogMessage(
                        Logger.MessageType.Received,
                        "TCP (from {0}): {1} bytes",
                        client.EndPoint,
                        read.ToString(CultureInfo.CurrentCulture)
                        );
                }

                if (read != 0)
                {
                    HandleReceiveFromClient(client, client.Buffer, read);

                    // listen for more data from this client

                    stream.BeginRead(client.Buffer, 0, client.Buffer.Length, new AsyncCallback(TcpReceiveCallback), client);
                    return;
                }
            }
            catch (System.IO.IOException)
            {
                // client disconnected, so we can no longer read...proceed to close socket
            }
            catch (Exception ex)
            {
                // Some other exception happened, we don't want this to be unhandled so we take this opportunity to log it
                // and to proceed to close the socket

                Logger.LogError("Exception caught during TcpReceiveCallback: {0}\n", ex.ToString());
            }

            // End connection and remove from client dictionary

            try
            {
                client.LogMessage(Logger.MessageType.Disconnect, "TCP Client ({0})", client.EndPoint);

                if (client.State == Client.ClientState.Dual)
                {
                    // If we had dual sockets, not we only have UDP

                    client.State = Client.ClientState.UDP;
                }
                else
                {
                    // We only had a TCP socket for this client, so now the client is dead

                    if (mainClient != null && client.EndPoint.Equals(mainClient.ToString()))
                    {
                        mainClient = null;
                    }

                    lock (clientDictionary)
                    {
                        clientDictionary.Remove(client.TcpClient.Client.RemoteEndPoint);
                    }

                    client.TcpClient.Close();
                    Logger.UnassignClientColor(client.LoggingColor);

                    client = null;
                }
            }
            catch (Exception ex)
            {
                // This probably indicates that the TcpClient could not be closed. We catch/log this exception here
                // for debugging and to avoid it being unhandled.

                Logger.LogError("Exception caught during TcpReceiveCallback (at end connection phase): {0}\n", ex.ToString());
            }
        }


        private void UDPForwardCallback(IAsyncResult result)
        {

            byte[] read;

            UdpState state = (UdpState)result.AsyncState;
            UdpClient udpClient = state.Client;
            

            if (udpClient.Client == null)
            {
                // Server is probably shutting down
                return;
            }

            read = udpClient.EndReceive(result, ref state.EndPoint);
            IPEndPoint srcEndPoint = state.EndPoint;

            if (SimpleVpnServer.OutputData)
            {
                Console.WriteLine(
                    "[{0}] {1}",
                    DateTime.Now.ToString(),
                    String.Format(CultureInfo.CurrentCulture, "Received UDP ForwardCallback (from {0}): {1} bytes", srcEndPoint.ToString(), read.Length)
                    );
            }

            //get actual destination info
            AddressBytes actualDestAddress;
            lock (originalSourceDictionary)
            {
                if (originalSourceDictionary.TryGetValue(srcEndPoint, out actualDestAddress)){
                    
                } else {
                    Console.WriteLine("No source found for {0}", srcEndPoint.ToString());
                    udpClient.BeginReceive(new AsyncCallback(UDPForwardCallback), state);
                    return;
                }
            }

            Byte[] dataOut; 

            PacketUtils.makeHeader( 
                read.Length,
                srcEndPoint.Address.GetAddressBytes(),
                BitConverter.GetBytes(actualDestAddress.address),
                (ushort) srcEndPoint.Port,
                actualDestAddress.port,
                out dataOut
            );
            
            //Copy in the actual data
            Array.Copy(read, 0, dataOut, PacketUtils.IPV4_TOTAL_LENGTH, read.Length);

            PacketUtils.FULL_HEADER_V4 fullHeader = PacketUtils.PinV4FullHeader(dataOut);

            Client mainOne;
            lock (clientDictionary)
            {
                if (clientDictionary.TryGetValue(mainClient, out mainOne))
                {
                    if (SimpleVpnServer.OutputData)
                    {
                        PacketUtils.ReadPacket(mainOne, fullHeader);
                    }
                    
                    mainOne.Send(dataOut, dataOut.Length);

                    if (SimpleVpnServer.OutputData)
                    {
                        mainOne.LogMessage(
                            Logger.MessageType.Received,
                            "Data back to main client (from {0}): {1} bytes",
                            srcEndPoint.ToString(),
                            dataOut.Length
                            );
                    }

                    packetCounter.TotalForwardedBackToClient++;
                }
                else 
                {
                    Console.WriteLine("main client not found?");
                }
            }

            udpClient.BeginReceive(new AsyncCallback(UDPForwardCallback), state);
        }

        


        private void HandleReceiveFromClient(Client client, byte[] buffer, int length)
        {
            packetCounter.TotalReceivedFromClient++;
            packetCounter.TotalBytesReceivedFromClient += length;

            PacketUtils.FULL_HEADER_V4 fullHeader = PacketUtils.PinV4FullHeader(buffer);

            int controlCode = Convert.ToInt32(fullHeader.ControlHeader.controlValue);

            VPN_CONTROL code;

            if (Enum.IsDefined(typeof(VPN_CONTROL), controlCode))
            {
                code = (VPN_CONTROL)controlCode;
            }
            else
            {
                client.LogMessage(Logger.MessageType.Received, "Received invalid control code");
                return;
            }

            switch (code)
            {
                case VPN_CONTROL.VPN_CONTROL_DISCONNECT:
                    client.LogMessage(Logger.MessageType.Received, "Received DISCONNECT");
                    packetCounter.TotalControlMessagesReceivedFromClient++;
                    return;
                case VPN_CONTROL.VPN_CONTROL_KEEP_ALIVE:
                    client.LogMessage(Logger.MessageType.Received, "-------------------------Received KEEP_ALIVE-------------------------");
                    packetCounter.TotalControlMessagesReceivedFromClient++;
                    return;
                case VPN_CONTROL.VPN_CONTROL_PACKET:
                    break;
            }
            
            //Determine protocol
            switch (fullHeader.IpHeader.Protocol)
            {
                case 1: // icmpv4, currently not supported

                    if (SimpleVpnServer.OutputData)
                    {
                        client.LogMessage(Logger.MessageType.Received, "Received IP");
                    }
                    packetCounter.TotalOtherReceivedFromClient++;

                    break;

                case 6: // tcp, currently not supported

                    if (SimpleVpnServer.OutputData)
                    {
                        client.LogMessage(Logger.MessageType.Received, "Received tcp");
                    }
                    packetCounter.TotalTCPReceivedFromClient++;
                    break;
                case 17: // udp

                    if (SimpleVpnServer.OutputData)
                    {
                        client.LogMessage(Logger.MessageType.Received, "Received udp");
                    }

                    packetCounter.TotalUDPReceivedFromClient++;

                    if (SimpleVpnServer.OutputData)
                    {
                        PacketUtils.ReadPacket(client, fullHeader);
                    }

                    if (SimpleVpnServer.Forward)
                    {
                        UInt16 srcPort = PacketUtils.ReverseByteOrder(fullHeader.IpProtocolHeader.UdpHeader.SourcePort);
                        UInt16 dstPort = PacketUtils.ReverseByteOrder(fullHeader.IpProtocolHeader.UdpHeader.DestinationPort);

                        IPAddress dstAddr = new IPAddress(fullHeader.IpHeader.DestinationAddressBytes);
                        IPEndPoint dest = new IPEndPoint(dstAddr, dstPort);

                        //Store original source for mapping later on when we receive a callback
                        lock (originalSourceDictionary)
                        {
                            AddressBytes srcAddr = new AddressBytes();
                            srcAddr.address = fullHeader.IpHeader.SourceAddressBytes;
                            srcAddr.port = fullHeader.IpProtocolHeader.UdpHeader.SourcePort;
                            originalSourceDictionary[dest] = srcAddr;
                        }

                        int dataSize = length - PacketUtils.IPV4_TOTAL_LENGTH;

                        Byte[] dataOut = new Byte[dataSize];
                        Array.Copy(buffer, PacketUtils.IPV4_TOTAL_LENGTH, dataOut, 0, dataSize);

                        Client forwardClient;
                        UdpState state = new UdpState();
                        state.EndPoint = dest;

                        bool alreadyExist = false;
                        lock (clientDictionary)
                        {
                            if (clientDictionary.TryGetValue(dest, out forwardClient))
                            {
                                switch (forwardClient.State)
                                {
                                    case Client.ClientState.Dual:
                                    case Client.ClientState.UDP:

                                        // Update the client in case there was a socket disconnect inbetween sends and the endpoint port changed,
                                        // also this operation will cause the UDP timer to be reset, which will keep the client connected

                                        forwardClient.ResetUdpTimer();
                                        alreadyExist = true;
                                        break;

                                    case Client.ClientState.TCP:


                                        forwardClient.LogMessage(Logger.MessageType.FlowEstablish, "We should not get this since TCP is not supported for forwarding as of yet", dest.ToString());
                                        alreadyExist = true;
                                        break;

                                    case Client.ClientState.None:

                                        // This is probably a previously expired UDP client, bring it back to life

                                        forwardClient.State = Client.ClientState.UDP;
                                        forwardClient.ResetUdpTimer();
                                        state.Client = forwardClient.UdpClient.Client;

                                        if (SimpleVpnServer.OutputData)
                                        {
                                            forwardClient.LogMessage(Logger.MessageType.FlowEstablish, "reactivate UDP Client ({0})", dest.ToString());
                                        }
                                        alreadyExist = true;
                                        break;
                                }
                            }
                            else
                            {
                                UdpClient udpClient = new UdpClient();

                                state.Client = udpClient;

                                forwardClient = new Client(state);
                                forwardClient.LoggingColor = Logger.AssignClientColor();

                                clientDictionary.Add(dest, forwardClient);

                                if (SimpleVpnServer.OutputData)
                                {
                                    forwardClient.LogMessage(Logger.MessageType.FlowEstablish, "UDP Client ({0})", dest.ToString());
                                }

                            }
                        }
                        forwardClient.Send(dataOut, dataSize);

                        if (SimpleVpnServer.OutputData)
                        {
                            forwardClient.LogMessage(
                                Logger.MessageType.Received,
                                "Forward data (from {0} to {1}): {2} bytes",
                                client.EndPoint,
                                dest,
                                dataSize.ToString(CultureInfo.CurrentCulture)
                                );
                        }

                        if (!alreadyExist)
                        {
                            forwardClient.LogMessage(
                                Logger.MessageType.Received,
                                "Setting up to receive callback!"
                                );
                            state.Client.BeginReceive(new AsyncCallback(UDPForwardCallback), state);
                        }
                    }

                    
                    break;
                default: // unhandled protocol
                    if (SimpleVpnServer.OutputData)
                    {
                        client.LogMessage(Logger.MessageType.Received, "Received unknown protocol");
                        PacketUtils.ReadPacket(client, fullHeader);
                    }
                    packetCounter.TotalOtherReceivedFromClient++;

                    break;
            }

            return;
        }

        

        #endregion
    }
}
