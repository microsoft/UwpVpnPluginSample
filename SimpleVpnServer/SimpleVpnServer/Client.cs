using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Timers;

namespace SimpleVpnServer
{
    /// <summary>
    /// Client Implementation
    /// </summary>
    class Client
    {
        #region Constants

        /// <summary>
        /// Our default is a 25 second timeout for UDP flows 
        /// </summary>
        const int _udpTimeout = 25000;
        
        #endregion

        #region Private Members

        private Timer _udpTimer;
        private Server.UdpState _udpClient;

        #endregion

        #region Enums

        /// <summary>
        /// Used to represent the current connection state for a client (i.e. which sockets do they
        /// currently have connected to the server)
        /// </summary>
        public enum ClientState
        {
            None,
            TCP,
            UDP,
            Dual
        }

        #endregion

        #region Constructors

        /// <summary>
        /// Constructor for TCP clients
        /// </summary>
        /// <param name="tcpClient">TcpClient</param>
        /// <param name="buffer">Byte buffer</param>
        public Client(TcpClient tcpClient, byte[] buffer)
        {
            if (tcpClient == null)
            {
                throw new ArgumentNullException("tcpClient");
            }

            if (buffer == null)
            {
                throw new ArgumentNullException("buffer");
            }

            this.TcpClient = tcpClient;
            this.Buffer = buffer;
            this.State = ClientState.TCP;
        }

        /// <summary>
        /// Consructor for UDP clients
        /// </summary>
        /// <param name="udpClient">UdpState</param>
        public Client(Server.UdpState udpClient)
        {
            this.UdpClient = udpClient;
            this.Buffer = new byte[0];
            this.State = ClientState.UDP;
        }

        #endregion

        #region Properties

        /// <summary>
        /// Get the TcpClient instance associated with this Client
        /// </summary>
        public TcpClient TcpClient
        {
            get;
            set;
        }

        /// <summary>
        /// Get the UdpState instance associated with this Client. State contains
        /// both the UdpClient and the associated IPEndPoint
        /// </summary>
        public Server.UdpState UdpClient
        {
            get
            {
                return this._udpClient;
            }

            set
            {
                this._udpClient = value;
                
                // Start a new timer to monitor UDP flow timeout

                StartUdpTimer();
            }
        }

        /// <summary>
        /// Get the TCP client Buffer
        /// </summary>
        public byte[] Buffer
        {
            get;
            set;
        }

        /// <summary>
        /// Get the TcpClient stream for this client
        /// </summary>
        public NetworkStream NetworkStream
        {
            get
            {
                try
                {
                    return TcpClient.GetStream();
                }
                catch (InvalidOperationException)
                {
                    // The TCP socket has most likely been closed
                    return null;
                }
            }
        }

        /// <summary>
        /// Get the endpoint for this client (IP address and port)
        /// </summary>
        public string EndPoint
        {
            get
            {
                switch (State)
                {
                    case ClientState.UDP:
                    case ClientState.Dual:

                        return UdpClient.EndPoint.ToString();

                    case ClientState.TCP:

                        return TcpClient.Client.RemoteEndPoint.ToString();

                    default:

                        return String.Empty;
                }
            }
        }

        /// <summary>
        /// Stores state to indicate whether this client is connected on TCP, UDP, or dual sockets
        /// </summary>
        public ClientState State
        {
            get;
            set;
        }

        /// <summary>
        /// Sets the console logging color for this client, very helpful for distinguishing clients
        /// </summary>
        public ConsoleColor LoggingColor
        {
            get;
            set;
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Invoke the client to send traffic. We will always send via UDP if a UDP socket
        /// is connected, otherwise TCP will be used.
        /// </summary>
        /// <param name="data">Byte buffer</param>
        /// <param name="bytesToSend">Number of bytes to send from the buffer</param>
        /// <returns>ClientState - to indicate which transport type was used for the send</returns>
        public ClientState Send(byte[] data, int bytesToSend)
        {
            try
            {
                if (bytesToSend == 0 || data == null || data.Length == 0)
                {
                    return ClientState.None;
                }

                // Prefer UDP if available

                switch (State)
                {
                    case ClientState.UDP:
                    case ClientState.Dual:

                        // Send over UDP and reset the UDP timer now that the socket has been used

                        UdpClient.Client.SendAsync(data, bytesToSend, UdpClient.EndPoint);
                        ResetUdpTimer();

                        return ClientState.UDP;

                    case ClientState.TCP:

                        // Send over TCP

                        if (NetworkStream != null && NetworkStream.CanWrite)
                        {
                            NetworkStream.Write(data, 0, bytesToSend);
                            return ClientState.TCP;
                        }

                        return ClientState.None;
                }
            }
            catch(Exception ex)
            {
                Logger.LogError("Exception caught during Client Send: {0}\n", ex.ToString());
            }

            return ClientState.None;
        }

        /// <summary>
        /// Reset the UDP timer, usually called after we have seen activity from the
        /// UDP socket
        /// </summary>
        public void ResetUdpTimer()
        {
            this._udpTimer.Stop();
            this._udpTimer.Start();
        }

        /// <summary>
        /// Stops the UDP timer
        /// </summary>
        public void StopUdpTimer()
        {
            this._udpTimer.Stop();
        }

        /// <summary>
        /// Logs a message to the console using this client's logging color
        /// </summary>
        /// <param name="message">Message string to log with formatting information</param>
        /// <param name="args">Objects to use when formatting message</param>
        public void LogMessage(Logger.MessageType type, string message, params object[] args)
        {
            Logger.LogMessage(this.LoggingColor, type, message, args);
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// Creates a new timer which will be used to track UDP flow expiration.
        /// </summary>
        private void StartUdpTimer()
        {
            // If the timer is already created, we just reset it

            if (this._udpTimer != null)
            {
                ResetUdpTimer();
                return;
            }

            // Create a new timer with default timeout (25 seconds) and hook up it's event handler

            this._udpTimer = new Timer(_udpTimeout);
            this._udpTimer.Elapsed += new ElapsedEventHandler(OnUdpTimeout);

            // Only raise the event the first time Interval elapses

            this._udpTimer.AutoReset = false;

            // Start the timer

            this._udpTimer.Start();
        }
        
        #endregion

        #region Event Handlers

        /// <summary>
        /// This event handler is called when a UDP timer has timed out. This means that our
        /// UDP socket has not been used recently and that it's flow is likely 
        /// expired, rendering the socket unusable for traffic forwarding. We therefore
        /// update the client state to indicate that it no longer has a valid UDP transport.
        /// </summary>
        /// <param name="source">object</param>
        /// <param name="e">ElapsedEventArgs</param>
        private void OnUdpTimeout(object source, ElapsedEventArgs e)
        {
            switch (this.State)
            {
                case ClientState.Dual:

                    // Fall back to TCP
                    this.State = ClientState.TCP;
                    break;

                case ClientState.UDP:

                    // This client no longer has a valid transport
                    this.State = ClientState.None;
                    break;
            }

            this.LogMessage(Logger.MessageType.FlowExpire, "UDP Client ({0})", UdpClient.EndPoint.ToString());
        }

        #endregion
    }
}
