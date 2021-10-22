using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

namespace SimpleVpnServer
{
    class Logger
    {
        #region Enums

        /// <summary>
        /// Used to indicate which type of event has occurred
        /// </summary>
        public enum MessageType
        {
            Connect,
            Reconnect,
            Disconnect,
            FlowEstablish,
            Sent,
            Received,
            FlowExpire,
            Error
        }

        #endregion

        #region Locks

        /// <summary>
        /// A lock is required as logging requests can come from different threads and we
        /// want to ensure that the various logging messages do not interrupt/intersect each other
        /// </summary>
        private static Object loggingLock = new Object();

        #endregion

        #region Private Members

        /// <summary>
        /// This list stores the available colors that can be assigned to connected clients. Each client
        /// should receive a unique logging color to ensure that it's output is easily identifable on the
        /// console. We only need to support two clients currently.
        /// </summary>
        private static List<ConsoleColor> availableColors = new List<ConsoleColor>()
        {
            ConsoleColor.Yellow,
            ConsoleColor.Cyan
        };

        #endregion

        #region Methods

        /// <summary>
        /// Used to assign a unique logging color to each client. When a new client connects, this method
        /// will be called to find the next available color to assign to the client
        /// </summary>
        /// <returns>ConsoleColor</returns>
        public static ConsoleColor AssignClientColor()
        {
            // Default to gray color

            ConsoleColor color = ConsoleColor.Gray;

            // Are there still colors available to assign?

            if (availableColors.Count > 0)
            {
                // Pop the next color and assign it to the caller

                color = availableColors[0];
                availableColors.RemoveAt(0);
            }

            return color;
        }

        /// <summary>
        /// When a client disconnects, this method should be called to return that clients logging color
        /// to the list of available colors
        /// </summary>
        /// <param name="color">The ConsoleColor to unassign</param>
        public static void UnassignClientColor(ConsoleColor color)
        {
            // Put the color back into the list so that it can be allocated again

            availableColors.Add(color);
        }

        /// <summary>
        /// Logs a message to the console, prefixed with a timestamp
        /// </summary>
        /// <param name="message">Message string to log with formatting information</param>
        /// <param name="args">Objects to use when formatting message</param>
        public static void LogMessage(string message, params object[] args)
        {
            lock (loggingLock)
            {
                Console.WriteLine(
                    "[{0}] {1}",
                    DateTime.Now.ToString(),
                    String.Format(CultureInfo.CurrentCulture, message, args)
                    );

                using (StreamWriter outputFile = makeStreamWriter())
                {
                    outputFile.WriteLine(
                    "[{0}] {1}",
                    DateTime.Now.ToString(),
                    String.Format(CultureInfo.CurrentCulture, message, args)
                    );
                }
            }
        }

        private static StreamWriter makeStreamWriter()
        {
            String date = ".{0}.{1}.{2}";
            date = String.Format(date, DateTime.Now.Year, DateTime.Now.Month, DateTime.Now.Day);
            Directory.CreateDirectory("C://SampleServerLog");
            return new StreamWriter("C://SampleServerLog/ServerLog" + date + ".txt", true);
        }

        /// <summary>
        /// Logs a typed message to the console in the specified color, prefixed with a timestamp
        /// </summary>
        /// <param name="lineColor">Console color to use for the message</param>
        /// <param name="type">The type of message to be logged</param>
        /// <param name="message">Message string to log with formatting information</param>
        /// <param name="args">Objects to use when formatting message</param>
        public static void LogMessage(ConsoleColor lineColor, MessageType type, string message, params object[] args)
        {
            lock (loggingLock)
            {
                if (SimpleVpnServer.UseColor)
                    Console.ForegroundColor = lineColor;

                Logger.LogMessage(type, message, args);
                Console.ResetColor();
            }
        }

        /// <summary>
        /// Logs a typed message to the console, prefixed with a timestamp
        /// </summary>
        /// <param name="type">The type of message to be logged</param>
        /// <param name="message">Message string to log with formatting information</param>
        /// <param name="args">Objects to use when formatting message</param>
        public static void LogMessage(MessageType type, string message, params object[] args)
        {
            lock (loggingLock)
            {
                using (StreamWriter outputFile = makeStreamWriter())
                {
                    // Save current color for consistency 

                    ConsoleColor currentColor = Console.ForegroundColor;

                    // Output a time stamp

                    Console.Write("[{0}] ", DateTime.Now.ToString());
                    outputFile.Write("[{0}] ", DateTime.Now.ToString());

                    // Output the message type, color coded

                    if (SimpleVpnServer.UseColor)
                    {
                        switch (type)
                        {
                            case MessageType.Connect:
                            case MessageType.Reconnect:
                            case MessageType.FlowEstablish:

                                Console.ForegroundColor = ConsoleColor.Green;
                                break;

                            case MessageType.Disconnect:

                                Console.ForegroundColor = ConsoleColor.Magenta;
                                break;

                            case MessageType.Error:

                                Console.ForegroundColor = ConsoleColor.Red;
                                break;

                            case MessageType.Received:

                                Console.ForegroundColor = ConsoleColor.White;
                                break;

                            case MessageType.Sent:

                                Console.ForegroundColor = ConsoleColor.White;
                                break;

                            case MessageType.FlowExpire:

                                Console.ForegroundColor = ConsoleColor.Magenta;
                                break;

                            default:

                                Console.ForegroundColor = ConsoleColor.Gray;
                                break;
                        }
                    }

                    Console.Write("{0}: ", type);
                    outputFile.Write("{0}: ", type);
                    // Return to the original console color and output the rest of the message

                    Console.ForegroundColor = currentColor;
                    Console.WriteLine(message, args);
                    outputFile.WriteLine(message, args);
                }
            }
        }

        /// <summary>
        /// Logs an error message to the console in red color, prefixed with a timestamp
        /// </summary>
        /// <param name="message">Message string to log with formatting information</param>
        /// <param name="args">Objects to use when formatting message</param>
        public static void LogError(string message, params object[] args)
        {
            lock (loggingLock)
            {
                if (SimpleVpnServer.UseColor)
                    Console.ForegroundColor = ConsoleColor.Red;

                LogMessage(MessageType.Error, message, args);
                Console.ResetColor();
            }
        }

        #endregion
    }
}
