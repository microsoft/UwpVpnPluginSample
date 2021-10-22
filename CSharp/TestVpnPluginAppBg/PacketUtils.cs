using System;
using System.Globalization;
using System.Runtime.InteropServices;

using Windows.Networking;

namespace TestVpnPluginAppBg
{
    
    public enum VPN_CONTROL
    {
        VPN_CONTROL_PACKET = 0x1,
        VPN_CONTROL_DISCONNECT,
        VPN_CONTROL_KEEP_ALIVE,
        VPN_CONTROL_INVALID = -1
    };

    public struct PACKET_COUNTER
    {
        public int TotalSent;
        public int TotalUDPSent;
        public int TotalControlSent;
        public int TotalReceived;
        public int TotalControlReceived;
        public int TotalBytesSent;
        public int TotalBytesReceived;
        public int TotalKeepAliveSent;
    }
    class PacketUtils
    {
        public const int UDP_PROTOCOL_ID = 17;
        /// <summary>
        /// Used by Decapsulate: Structure to represent a IPv4 header
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct IPV4_HEADER
        {
            public byte VersionHeaderLengthByte;     // Offset 0
            public byte DifferentiatedServicesByte;  // Offset 1
            public ushort TotalLengthBytes;          // Offset 2
            public ushort Idenfication;              // Offset 4
            public ushort FlagsAndOffset;            // Offset 6
            public byte ttl;                         // Offset 8
            public byte Protocol;                    // Offset 9
            public ushort HeaderChecksumBytes;       // Offset 10
            public uint SourceAddressBytes;          // Offset 12
            public uint DestinationAddressBytes;     // Offset 16

            public ushort HeaderLength
            {
                get
                {
                    byte headerLength = VersionHeaderLengthByte;
                    headerLength <<= 4;
                    headerLength >>= 4;
                    headerLength *= 4;

                    return Convert.ToUInt16(headerLength);
                }
            }

            public byte Version
            {
                get
                {
                    return (byte)(VersionHeaderLengthByte >> 4);
                }
            }

            public string SourceAddress
            {
                get
                {
                    return String.Join(".", BitConverter.GetBytes(SourceAddressBytes));
                }
            }

            public string DestinationAddress
            {
                get
                {
                    return String.Join(".", BitConverter.GetBytes(DestinationAddressBytes));
                }
            }
        }

        /// <summary>
        /// Used by Decapsulate: Structure to represent a IPv6 header
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct IPV6_HEADER
        {
            public uint VersionClassFlow;     // 4 bits Version, 8 Traffic Class, 20 Flow Label.
            public ushort PayloadLength;      // Zero indicates Jumbo Payload hop-by-hop option.
            public byte NextHeader;           // Values are superset of IPv4's Protocol field.
            public byte HopLimit;
            public ushort SourceAddress0;     // Each address ushort represents a IPv6 address segment
            public ushort SourceAddress1;
            public ushort SourceAddress2;
            public ushort SourceAddress3;
            public ushort SourceAddress4;
            public ushort SourceAddress5;
            public ushort SourceAddress6;
            public ushort SourceAddress7;
            public ushort DestinationAddress0;
            public ushort DestinationAddress1;
            public ushort DestinationAddress2;
            public ushort DestinationAddress3;
            public ushort DestinationAddress4;
            public ushort DestinationAddress5;
            public ushort DestinationAddress6;
            public ushort DestinationAddress7;

            public string SourceAddress
            {
                get
                {
                    ushort[] segments = new ushort[] { SourceAddress0, SourceAddress1, SourceAddress2, SourceAddress3, SourceAddress4, SourceAddress5, SourceAddress6, SourceAddress7 };
                    return PacketUtils.IPv6AddressToString(segments);
                }
            }

            public string DestinationAddress
            {
                get
                {
                    ushort[] segments = new ushort[] { DestinationAddress0, DestinationAddress1, DestinationAddress2, DestinationAddress3, DestinationAddress4, DestinationAddress5, DestinationAddress6, DestinationAddress7 };
                    return PacketUtils.IPv6AddressToString(segments);
                }
            }
        }

        /// <summary>
        /// Structure to represent a TCP header
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct TCP_HEADER
        {
            public ushort SourcePort;
            public ushort DestinationPort;
            public uint SequenceNumber;
            public uint AcknowledgementNumber;
            public byte DataOffsetReservedAndNS;
            public byte ControlBits;
            public ushort Window;
            public ushort Checksum;
            public ushort UrgentPointer;
            public byte POptions;
        }

        /// <summary>
        /// Structure to represent a UDP header
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct UDP_HEADER
        {
            public ushort SourcePort;
            public ushort DestinationPort;
            public ushort Length;
            public ushort Checksum;
        }

        /// <summary>
        /// Structure to represent a ICMPv4 header
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct ICMP_HEADER_V4
        {
            public byte Type;
            public byte Code;
            public ushort Checksum;
            // We don't specify the full header, just enough to see what the packet is
        }

        /// <summary>
        /// Structure to represent a ICMPv6 header
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct ICMP_HEADER_V6
        {
            public byte Type;
            public byte Code;
            public ushort Checksum;
            // We don't specify the full header, just enough to see what the packet is
        }

        /// <summary>
        /// Structure to represent a IPv4 protocol header (e.g. TCP or UDP header etc)
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public struct IP_PROTOCOL_HEADER_V4
        {
            [FieldOffset(0)]
            public TCP_HEADER TcpHeader;
            [FieldOffset(0)]
            public UDP_HEADER UdpHeader;
            [FieldOffset(0)]
            public ICMP_HEADER_V4 IcmpV4Header;
        }

        /// <summary>
        /// Structure to represent a IPv6 protocol header (e.g. TCP or UDP header etc)
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public struct IP_PROTOCOL_HEADER_V6
        {
            [FieldOffset(0)]
            public TCP_HEADER TcpHeader;
            [FieldOffset(0)]
            public UDP_HEADER UdpHeader;
            [FieldOffset(0)]
            public ICMP_HEADER_V6 IcmpV6Header;
        }

        /// <summary>
        /// Structure to represent a "Full" IPv4 packet header (e.g. IP header + IP protocol header)
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public struct FULL_HEADER_V4
        {
            [FieldOffset(0)] internal CONTROL_HEADER ControlHeader;
            [FieldOffset(1)] internal IPV4_HEADER IpHeader;
            [FieldOffset(21)] internal IP_PROTOCOL_HEADER_V4 IpProtocolHeader;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CONTROL_HEADER
        {
            internal byte controlValue;
        }

        /// <summary>
        /// Structure to represent a "Full" IPv6 packet header (e.g. IP header + IP protocol header)
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public struct FULL_HEADER_V6
        {
            [FieldOffset(0)] internal CONTROL_HEADER ControlHeader;
            [FieldOffset(1)] internal IPV6_HEADER IpHeader;
            [FieldOffset(41)] internal IP_PROTOCOL_HEADER_V6 IpProtocolHeader;
        }

        /// <summary>
        /// Pins a byte array in memory and returns it cast as FULL_HEADER_V4
        /// </summary>
        /// <param name="packetBytes">Byte array, expected to represent a full IPv4 packet</param>
        /// <returns>FULL_HEADER_V4</returns>
        public static FULL_HEADER_V4 PinV4FullHeader(byte[] packetBytes)
        {
            GCHandle pinnedHeader = GCHandle.Alloc(packetBytes, GCHandleType.Pinned);
            FULL_HEADER_V4 header = (FULL_HEADER_V4)Marshal.PtrToStructure<FULL_HEADER_V4>(pinnedHeader.AddrOfPinnedObject());
            pinnedHeader.Free();

            return header;
        }

        /// <summary>
        /// Pins a byte array in memory and returns it cast as FULL_HEADER_V6
        /// </summary>
        /// <param name="packetBytes">Byte array, expected to represent a full IPv6 packet</param>
        /// <returns>FULL_HEADER_V6</returns>
        public static FULL_HEADER_V6 PinV6FullHeader(byte[] packetBytes)
        {
            GCHandle pinnedHeader = GCHandle.Alloc(packetBytes, GCHandleType.Pinned);
            FULL_HEADER_V6 header = (FULL_HEADER_V6)Marshal.PtrToStructure<FULL_HEADER_V6>(pinnedHeader.AddrOfPinnedObject());
            pinnedHeader.Free();

            return header;
        }

        /// <summary>
        /// Converts a IPv6 address (represented as an array of ushort/segments) to a string. Network
        /// order is assumed, so the ushorts will be switched to host order.
        /// </summary>
        /// <param name="addressSegments">ushort[] address segments</param>
        /// <returns>string</returns>
        public static string IPv6AddressToString(ushort[] addressSegments)
        {
            string strAddress = String.Empty;

            // Begin converting ushorts to hex strings
            foreach (ushort segment in addressSegments)
            {
                strAddress += String.Format(CultureInfo.InvariantCulture, "{0:x4}:", ReverseByteOrder(segment));
            }

            //
            // By instantiating a HostName with the full IPv6 address and then using the DisplayName property we will
            // receive back a compressed representation of the address. This avoids us having to do the work.
            //
            HostName host = new HostName(strAddress.TrimEnd(':'));
            return host.DisplayName;
        }

        /// <summary>
        /// Reverse byte order (we use this to convert from network order to host order, like ntohs)
        /// </summary>
        /// <param name="value">UInt16</param>
        /// <returns>UInt16</returns>
        public static UInt16 ReverseByteOrder(UInt16 value)
        {
            byte[] bytes = BitConverter.GetBytes(value);
            byte tempByte = bytes[0];
            bytes[0] = bytes[1];
            bytes[1] = tempByte;
            return BitConverter.ToUInt16(bytes, 0);
        }
    }
}
