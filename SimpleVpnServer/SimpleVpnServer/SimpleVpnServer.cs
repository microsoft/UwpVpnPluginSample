using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SimpleVpnServer
{
    class SimpleVpnServer
    {
        #region Return Codes

        private const int ERROR_SUCCESS = 0;
        private const int ERROR_INVALID_DATA = 13;
        private const int ERROR_INVALID_PARAMETER = 87;
        #endregion

        #region Constants

        private const string StartServerArg = "/Start";
        private const string ShowDataArg = "/ShowData";
        private const string NoColorArg = "/NoColor";
        private const string ServerPortArg = "/Port";
        private const string BufferArg = "/Buffer";
        private const string HelpArg = "/?";
        private const string TcpOnlyArg = "/TCP";
        private const string UdpOnlyArg = "/UDP";
        private const string ForwardArg = "/Forward";
        private const string PacketCounterArg = "/PacketCounter";

        #endregion

        #region Default setting values

        internal static bool OutputData = false;
        internal static int ServerPort = 443;
        internal static int BufferSize = 8192;
        internal static bool AcceptTcp = true;
        internal static bool AcceptUdp = true;
        internal static bool UseColor = true;
        internal static bool Forward = false;
        #endregion

        #region Main

        static void Main(string[] args)
        {
            // VPN Server instance

            Server vpnServer = new Server();
            Timer timer = null;

            try
            {
                Console.WriteLine();

                // Parse command line args

                if (args.Length > 0)
                {
                    // Help arg

                    if (CheckForArg(args, HelpArg))
                    {
                        ShowUsage();
                        Environment.Exit(ERROR_SUCCESS);
                    }

                    // At a minimum, we should have the start arg

                    if (!CheckForArg(args, StartServerArg))
                    {
                        ShowUsage();
                        Environment.Exit(ERROR_INVALID_PARAMETER);
                    }
                    else
                    {
                        // Show Data arg

                        if (CheckForArg(args, ShowDataArg))
                            OutputData = true;

                        if (CheckForArg(args, NoColorArg))
                            UseColor = false;

                        // TCP only arg

                        if (CheckForArg(args, TcpOnlyArg))
                            AcceptUdp = false;

                        // UDP only arg

                        if (CheckForArg(args, UdpOnlyArg))
                            AcceptTcp = false;
                        
                        //Forward Packets

                        if (CheckForArg(args, ForwardArg))
                            Forward = true;

                        //Packet Counter

                        if (CheckForArg(args, PacketCounterArg))
                        {
                            PacketChecker statusChecker = new PacketChecker(vpnServer);
                            var autoEvent = new AutoResetEvent(true);
                            timer = new Timer(statusChecker.PrintCounts, autoEvent, 1000, 10000);
                        }



                        // Server Port arg

                        if (CheckForArg(args, ServerPortArg))
                        {
                            string tmpPort = GetArgValue(args, ServerPortArg);
                            if (!String.IsNullOrEmpty(tmpPort))
                            {
                                try
                                {
                                    int iPort = Int32.Parse(tmpPort, CultureInfo.CurrentCulture);
                                    if (iPort < 1 || iPort > 65535)
                                    {
                                        throw new FormatException();
                                    }

                                    ServerPort = iPort;
                                }
                                catch (FormatException)
                                {
                                    Console.WriteLine("Invalid port value specified (port must be a numeric value in the range 1-65535)");
                                    Environment.Exit(ERROR_INVALID_PARAMETER);
                                }
                            }
                        }

                        // Receive buffer arg

                        if (CheckForArg(args, BufferArg))
                        {
                            string tmpBuffer = GetArgValue(args, BufferArg);
                            if (!String.IsNullOrEmpty(tmpBuffer))
                            {
                                try
                                {
                                    BufferSize = Int32.Parse(tmpBuffer, CultureInfo.CurrentCulture);
                                    if (BufferSize < 1)
                                    {
                                        throw new FormatException();
                                    }
                                }
                                catch (Exception ex)
                                {
                                    // Check for expected exception types

                                    if (ex.GetType() == typeof(OverflowException) ||
                                        ex.GetType() == typeof(FormatException))
                                    {
                                        Console.WriteLine("Invalid buffer value specified (please ensure that your value is numeric)");
                                        Environment.Exit(ERROR_INVALID_PARAMETER);
                                    }

                                    // Unexpected exception type, re-throw it

                                    throw;
                                }
                            }
                        }
                    }
                }
                else
                {
                    ShowUsage();
                    Environment.Exit(ERROR_INVALID_PARAMETER);
                }

                // Create the server and start listening for clients

                if (vpnServer.StartServer(ServerPort))
                {
                    // The server will run until someone presses q on the console, or the process is killed. We disconnect if we get a different value

                    while (!Console.ReadLine().Equals("q"))
                    {
                        vpnServer.Disconnect();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception caught during Main: {0}", ex.ToString());
                Environment.Exit(ERROR_INVALID_DATA);
            }
            finally
            {
                //Stop the timer
                if (timer != null)
                {
                    timer.Dispose();
                }

                // Stop the VPN server, if it's running
                vpnServer.StopServer();

                // Clean exit

                Environment.Exit(ERROR_SUCCESS);
            }
        }

        #endregion

        #region Command line helper methods

        /// <summary>
        /// Check for the presence of an optional argument
        /// </summary>
        /// <param name="args">Command line args to search through</param>
        /// <param name="argToFind">Command line arg to find</param>
        /// <returns>bool</returns>
        private static bool CheckForArg(string[] args, string argToFind)
        {
            if (args == null)
                return false;

            if (String.IsNullOrEmpty(argToFind))
                return false;

            return !String.IsNullOrEmpty(Array.Find(args, s => s.Equals(argToFind, StringComparison.OrdinalIgnoreCase)));
        }

        /// <summary>
        /// Retrieve the value of an argument specified in "/arg value" format
        /// </summary>
        /// <param name="args">Command line args to search through</param>
        /// <param name="argToFind">Command line arg to find</param>
        /// <returns>string</returns>
        private static string GetArgValue(string[] args, string argToFind)
        {
            if (args == null)
                return String.Empty;

            if (String.IsNullOrEmpty(argToFind))
                return String.Empty;

            for (int x = 0; x < args.Length; x++)
            {
                if ((args[x].Equals(argToFind, StringComparison.OrdinalIgnoreCase)) &&
                    (x != args.Length - 1))
                {
                    return args[x + 1];
                }
            }

            return String.Empty;
        }

        /// <summary>
        /// Output the application usage/syntax information
        /// </summary>
        /// <returns>int</returns>
        public static void ShowUsage()
        {
            Console.WriteLine("Syntax:\n");
            Console.WriteLine("  {0} {1} [options]\n", AppDomain.CurrentDomain.FriendlyName, StartServerArg);
            Console.WriteLine("Options:\n");
            Console.WriteLine("  {0} <port> - set the server listening port (default: {1})", ServerPortArg, ServerPort);
            Console.WriteLine("  {0} - only listen for TCP connections (default: TCP and UDP)", TcpOnlyArg);
            Console.WriteLine("  {0} - only listen for UDP connections (default: TCP and UDP)", UdpOnlyArg);
            Console.WriteLine("  {0} <bytes> - set the send/receive tcp buffer size (default: {1})", BufferArg, BufferSize);
            Console.WriteLine("  {0} - displays sends/receives on the console.", ShowDataArg);
            Console.WriteLine("  {0} - disables color coded logging.", NoColorArg);
            Console.WriteLine("  {0} - forward packets (for testing)", ForwardArg);
            Console.WriteLine("  {0} - displays this message.", HelpArg);
            Console.WriteLine("\nExample:\n");
            Console.WriteLine("  {0} {1} {2} 443 {3} 8192", AppDomain.CurrentDomain.FriendlyName, StartServerArg, ServerPortArg, BufferArg);
        }

        #endregion


    }

    class PacketChecker
    {
        Server server;
        public PacketChecker(Server server)
        {
            this.server = server;
        }

        public void PrintCounts(Object stateInfo)
        {
            if (server.isConnected())
            {
                String message = "Packet Count: TotalPacketsReceived: {0}, UDPReceived: {1}, TCPReceived: {2}, ControlReceived: {3}, OtherReceived: {4} TotalSentBack: {5}, TotalBytesReceived: {6}";
                Logger.LogMessage(
                    message, 
                    server.packetCounter.TotalReceivedFromClient,
                    server.packetCounter.TotalUDPReceivedFromClient,
                    server.packetCounter.TotalTCPReceivedFromClient,
                    server.packetCounter.TotalControlMessagesReceivedFromClient,
                    server.packetCounter.TotalOtherReceivedFromClient,
                    server.packetCounter.TotalForwardedBackToClient,
                    server.packetCounter.TotalBytesReceivedFromClient
                    );
            } 
        }
    }
}
