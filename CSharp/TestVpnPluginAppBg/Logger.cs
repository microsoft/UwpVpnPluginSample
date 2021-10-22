using System;
using Windows.Networking.Vpn;

namespace TestVpnPluginAppBg
{
    #region Enums

    /// <summary>
    /// Used to control the logging level of the plug-in
    /// </summary>
    public enum VPN_PLUGIN_LOG_LEVEL
    {
        VPN_PLUGIN_LOG_LEVEL_LOW = 0x1,
        VPN_PLUGIN_LOG_LEVEL_MEDIUM,
        VPN_PLUGIN_LOG_LEVEL_HIGH
    };

    /// <summary>
    /// logLevel
    /// Determines how detailed logs are, can be either low, medium or high. The higher it is, the more logs.
    /// 
    /// packetCapture
    /// This is used to specify whether the plug-in should output packet information during encapsulation
    /// and decapsulation (for debugging purposes). The packets are output via the standard platform
    /// logging API (so they will appear alongside other plug-in logs in ETW). This feature is useful
    /// for seeing what type of traffic is flowing through the plug-in (e.g. TCP/UDP/ICMP etc)
    /// 
    /// bufferCapture
    /// This is used to specify whether the plug-in should output raw packet buffers during encapsulation
    /// and decapsulation (for debugging purposes). The buffer bytes are output via the standard platform
    /// logging API (so they will appear alongside other plug-in logs in ETW). This is useful for debugging
    /// full packets byte by byte, but not recommended for large packets as the logging message may become
    /// too long to be successfully output
    /// </summary>
    public struct LoggingSettings
    {
        public VPN_PLUGIN_LOG_LEVEL logLevel;
        public bool packetCapture;
        public bool bufferCapture;
    };

    #endregion
    public sealed class Logger
    {
        private static readonly Lazy<Logger> lazy = new Lazy<Logger> (() => new Logger());

        public static Logger Instance { get { return lazy.Value; } }

        internal LoggingSettings loggingSettings;
        
        private Logger() 
        {
            loggingSettings = new LoggingSettings();
            loggingSettings.logLevel = VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM;
        }

        public void LogMessage(VpnChannel channel, VPN_PLUGIN_LOG_LEVEL level, string message)
        {
            if (level <= loggingSettings.logLevel)
            {
                channel.LogDiagnosticMessage(message);
            }
        }
    }
}
