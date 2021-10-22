using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

using Windows.Data.Xml.Dom;
using Windows.Networking;
using Windows.Networking.Vpn;
using Windows.Networking.Sockets;
using Windows.Security.Cryptography.Certificates;
using Windows.Media.Protection;
using System.Diagnostics;

namespace TestVpnPluginAppBg
{
    /// <summary>
    /// Used to represent a type of VPN authentication to perform along with the expected credentials
    /// that should be provided by the user
    /// </summary>
    /// 
    [StructLayout(LayoutKind.Sequential)]
    public struct VPN_AUTHENTICATION
    {
        public VpnCredentialType authType;
        public string expectedUser;
        public string expectedPass;
        public string expectedPin;
        public string expectedNewPass;
        public string certSubject;
        public bool useSingleSignOn;
    };

    /// <summary>
    /// Used to represent whether plugin is in exception mode and where exceptions will be thrown
    /// </summary>
    /// 
    [StructLayout(LayoutKind.Sequential)]
    public struct EXCEPTION_MODE_FLAGS
    {
        public bool exMode;
        public bool exConnect_1;
        public bool exConnect_2;
        public bool exConnect_3;
        public bool exEncapsulate;
        public bool exDecapsulate;
        public bool exDisconnect;
    };

    /// <summary>
    /// Used to represent the transport type(s) that the plug-in can use to connect to the VPN server
    /// </summary>
    public enum VPN_PLUGIN_TRANSPORT_TYPE
    {
        VPN_PLUGIN_TRANSPORT_TYPE_TCP,
        VPN_PLUGIN_TRANSPORT_TYPE_UDP,
        VPN_PLUGIN_TRANSPORT_TYPE_DUAL,
        VPN_PLUGIN_TRANSPORT_TYPE_MAX
    };

    class CustomConfiguration
    {
        public bool IsV2 = false;
        public VpnChannelConfiguration cfg;
        public VpnTrafficFilterAssignment trafficFilterAssignment = new VpnTrafficFilterAssignment();
        public List<VPN_AUTHENTICATION> authentications = new List<VPN_AUTHENTICATION>();
        public List<IReadOnlyList<IVpnCustomPrompt>> preAuthCustomPrompts = new List<IReadOnlyList<IVpnCustomPrompt>>();
        public List<IReadOnlyList<IVpnCustomPrompt>> postAuthCustomPrompts = new List<IReadOnlyList<IVpnCustomPrompt>>();
        public Certificate authCert = null;

        public VPN_PLUGIN_TRANSPORT_TYPE transportType = VPN_PLUGIN_TRANSPORT_TYPE.VPN_PLUGIN_TRANSPORT_TYPE_TCP;

        public bool connectedTcp = false;
        public bool connectedUdp = false;

        public string clientIpV4 = String.Empty;
        public string clientIpV6 = String.Empty;
        public string clientIpReconnectV4 = String.Empty;
        public string clientIpReconnectV6 = String.Empty;
        public string portServiceName = String.Empty;

        public SocketProtectionLevel protectionLevel = SocketProtectionLevel.PlainSocket;

        public VpnRouteAssignment routeAssignment = new VpnRouteAssignment();
        public List<VpnRoute> ipv4InclusionRoutes = new List<VpnRoute>();
        public List<VpnRoute> ipv4ExclusionRoutes = new List<VpnRoute>();
        public List<VpnRoute> ipv6InclusionRoutes = new List<VpnRoute>();
        public List<VpnRoute> ipv6ExclusionRoutes = new List<VpnRoute>();
        public bool excludeLocalSubnets = false;


        public VpnNamespaceAssignment namespaceAssignment = new VpnNamespaceAssignment();
        public List<VpnNamespaceInfo> namespaceList = new List<VpnNamespaceInfo>();

        //v2 Addition
        public VpnDomainNameAssignment domainnameAssignment = new VpnDomainNameAssignment();
        public List<VpnDomainNameInfo> domainnameList = new List<VpnDomainNameInfo>();

        public VpnSystemHealth healthStatus;

        /// <summary>
        /// Default frame size to use. This is only used if no other frame size is specified via custom
        /// configuration XML.
        /// </summary>
        public UInt32 maxFrameSize = 1501;

        /// <summary>
        /// Default port to use when connecting to the VPN server. This is only used if no other port was
        /// specified via custom configuration XML.
        /// </summary>
        internal string defaultPort = "443";

        /// <summary>
        /// This member is used to keep track of whether we are being asked to connect for the first time
        /// or whether we are reconnecting. Depending on the plug-in configuration, we may want to do
        /// different things during reconnect, so after the first connection we will set this to true
        /// </summary>
        internal bool IsReconnect;

        Logger logger = Logger.Instance;

        internal VpnChannel channel;

        EXCEPTION_MODE_FLAGS exceptionFlags;

        //ActivateForeground Additions
        public bool TestActivateForeground = false;
        

        public CustomConfiguration(VpnChannel channel, bool isReconnect, EXCEPTION_MODE_FLAGS exceptionFlags)
        {
            IsReconnect = isReconnect;
            this.channel = channel;
            this.exceptionFlags = exceptionFlags;

            //
            // Obtain the VPN profile configuration. This will give us the list of VPN servers to work with and any other
            // configuration details (e.g. ports, custom settings, etc) that are present within the provisioned VPN profile
            //
            cfg = channel.Configuration;

            //
            // Sanity check the VPN profile configuration to ensure we at least have one VPN server to work with
            //
            if (cfg == null)
            {
                logger.LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Error: Received a null configuration.");
                return;
            }

            if (cfg.ServerHostNameList.Count == 0)
            {
                logger.LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Error: Did not receive a server host name to connect to.");
                return;
            }

            this.parseConfiguration();
        }


        // *****************************
        // BEGIN: Custom Configuration parsing
        //
        // Parse custom configuration from the channel config. For this plug-in implementation, we expect the client ip address
        // and server port to be present within the CustomField. This is a simple way to provide each VPN client with its own
        // IP address for test purposes.
        //                
        // The schema for this custom configuration implementation is expected to be similar to:
        //               
        // <pluginschema>
        //  <v2>
        //   <perapp>
        //        <appId>
        //          <name>C:\Windows\System32\PING.EXE</name>
        //          <type>filepath</type>
        //          <remoteaddressranges>172.10.10.12-172.10.10.15</remoteaddressranges>
        //          <protocol>tcp</protocol>
        //          <remoteportranges>10-30</remoteportranges>
        //         <appId>
        //        <appId>
        //          <name>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</name>
        //          <type>filepath</type>
        //          <remoteaddressranges>172.10.10.12-172.10.10.15</remoteaddressranges>
        //          <protocol>tcp</protocol>
        //          <remoteportranges>10-30</remoteportranges>
        //         <appId>
        //    </perapp>
        //   </v2>
        //   <ipAddress>172.10.10.10</ipAddress>
        //   <ipAddressv6>fe79::91:8</ipAddressv6>
        //   <port>443</port>
        //   <transport>tcp</transport>
        //   <maxframesize>1501</maxframesize>
        //   <credentials>
        //     <credential>
        //       <type>userpass</type>
        //       <user>nick</user>
        //       <pass>foobar</pass>
        //       <sso>true</sso>
        //     </credential>
        //     <credential>
        //       <type>passchange</type>
        //       <user>nick</user>
        //       <pass>foobar</pass>
        //       <newpass>somepass</newpass>
        //     </credential>
        //     <credential>
        //       <type>protectedcert</type>
        //       <certsubject>mysubject</certsubject>
        //     </credential>
        //   </credentials>
        //   <networksettings>
        //     <routes>
        //       <includev4>
        //         <route>
        //           <address>172.10.10.0</address>
        //           <prefix>24</prefix>
        //         </route>
        //       </includev4>
        //       <excludev4>
        //         <route>
        //           <address>172.10.10.128</address>
        //           <prefix>25</prefix>
        //         </route>
        //       </excludev4>
        //       <includev6>
        //         <route>
        //           <address>fe7f::0:0</address>
        //           <prefix>64</prefix>
        //         </route>
        //       </includev6>
        //       <excludev6>
        //         <route>
        //           <address>fe7f::90:12</address>
        //           <prefix>128</prefix>
        //         </route>
        //       </excludev6>
        //       <excludelocalsubnets>false</excludelocalsubnets>
        //     </routes>
        //     <namespaces>
        //       <proxyautoconfig>http://proxy.corp.foobar.com</proxyautoconfig>
        //       <namespace>
        //         <space>.corp.foobar.com</space>
        //         <dnsservers>
        //           <server>172.10.10.1</server>
        //           <server>172.10.10.2</server>
        //         </dnsservers>
        //         <proxyservers>
        //           <server>172.10.10.30</server>
        //           <server>172.10.10.31</server>
        //         </proxyservers>
        //       </namespace>
        //     </namespaces>
        //   </networksettings>
        //   <reconnect>
        //     <ipAddress>172.10.10.20</ipAddress>
        //   </reconnect>
        //   <loglevel>medium</loglevel>
        //   <packetcapture>true</packetcapture>
        //   <buffercapture>true</buffercapture>
        //   <customui>
        //     <preauth>
        //       <prompt>
        //         <combobox>
        //           <label>some label</label>
        //           <compulsory>true</compulsory>
        //           <bordered>false</bordered>
        //           <options>
        //             <option>option 1</option>
        //             <option>option 2</option>
        //           </options>
        //         </combobox>
        //       </prompt>
        //     </preauth>
        //     <postauth>
        //       <prompt>
        //         <editbox>
        //           <label>some label</label>
        //           <defaulttext>some text</defaulttext>
        //           <compulsory>true</compulsory>
        //           <noecho>true</noecho>
        //           <bordered>false</bordered>
        //         </editbox>
        //         <combobox>
        //           <label>some label</label>
        //           <compulsory>true</compulsory>
        //           <bordered>false</bordered>
        //           <options>
        //             <option>option 1</option>
        //             <option>option 2</option>
        //           </options>
        //         </combobox>
        //       </prompt>
        //       <prompt>
        //         <textbox>
        //           <label>some label</label>
        //           <text>some text</text>
        //           <compulsory>true</compulsory>
        //           <bordered>false</bordered>
        //         </textbox>
        //         <checkbox>
        //           <label>some label</label>
        //           <checked>true</checked>
        //           <bordered>false</bordered>
        //         </checkbox>
        //         <errorbox>
        //           <bordered>false</bordered>
        //         </errorbox>
        //       </prompt>
        //     </postauth>
        //   </customui>
        //   <exception>
        //     <func>connect_1</func>
        //     <!-- connect_1: before associate transport-->
        //     <!-- connect_2: after associate transport before channel start -->
        //     <!-- connect_3: after channel start -->
        //     <!-- encapsulate -->
        //     <!-- decapsulate -->
        //     <!-- disconnect -->
        //   </exception>
        // </pluginschema>
        //
        internal void parseConfiguration()
        {
            if (!String.IsNullOrWhiteSpace(cfg.CustomField))
            {
                XmlDocument doc = new XmlDocument();
                doc.LoadXml(cfg.CustomField);

                IXmlNode root = doc.SelectSingleNode("pluginschema");

                if (root != null)
                {
                    foreach (IXmlNode rootChild in root.ChildNodes)
                    {
                        switch (rootChild.NodeName)
                        {
                            //v2 Addition
                            case "v2":
                                IsV2 = true;
                                foreach (IXmlNode v2Child in rootChild.ChildNodes)
                                {
                                    switch (v2Child.NodeName)
                                    {
                                        case "perapp":
                                            foreach (IXmlNode perAppChild in v2Child.ChildNodes)
                                            {
                                                // Going over each appid specified in the schema
                                                string appname = string.Empty;
                                                VpnIPProtocol vpnIpProtocol = VpnIPProtocol.None;
                                                string remoteaddressRanges = string.Empty;
                                                string remoteportRanges = string.Empty;
                                                string appClaims = string.Empty;
                                                VpnAppIdType apptype = VpnAppIdType.PackageFamilyName;
                                                VpnTrafficFilter filter = new VpnTrafficFilter(new VpnAppId(apptype, appname));
                                                foreach (IXmlNode appIdChild in perAppChild.ChildNodes)
                                                {
                                                    switch (appIdChild.NodeName)
                                                    {
                                                        case "name":
                                                            appname = appIdChild.InnerText;
                                                            break;
                                                        case "type":
                                                            switch (appIdChild.InnerText)
                                                            {
                                                                case "filepath":
                                                                    apptype = VpnAppIdType.FilePath;
                                                                    break;
                                                                case "fullyqualifiedbinaryname":
                                                                    apptype = VpnAppIdType.FullyQualifiedBinaryName;
                                                                    break;
                                                                case "packagefamilyname":
                                                                    apptype = VpnAppIdType.PackageFamilyName;
                                                                    break;
                                                            }
                                                            break;
                                                        case "remoteaddressranges":
                                                            remoteaddressRanges = appIdChild.InnerText;
                                                            break;
                                                        case "remoteportranges":
                                                            remoteportRanges = appIdChild.InnerText;
                                                            break;
                                                        case "appclaims":
                                                            appClaims = appIdChild.InnerText;
                                                            break;
                                                        case "protocol":
                                                            switch (appIdChild.InnerText)
                                                            {
                                                                case "tcp":
                                                                    vpnIpProtocol = VpnIPProtocol.Tcp;
                                                                    break;
                                                                case "udp":
                                                                    vpnIpProtocol = VpnIPProtocol.Udp;
                                                                    break;
                                                            }
                                                            break;
                                                    }
                                                }
                                                if (appname != string.Empty)
                                                {
                                                    filter.AppId.Type = apptype;
                                                    filter.AppId.Value = appname;
                                                }
                                                filter.Protocol = vpnIpProtocol;
                                                if (remoteaddressRanges != string.Empty)
                                                {
                                                    filter.RemoteAddressRanges.Add(remoteaddressRanges);
                                                }
                                                if (remoteportRanges != string.Empty)
                                                {
                                                    filter.RemotePortRanges.Add(remoteportRanges);
                                                }
                                                if (appClaims != string.Empty)
                                                {
                                                    filter.AppClaims.Add(appClaims);
                                                }
                                                trafficFilterAssignment.TrafficFilterList.Add(filter);
                                            }
                                            break;
                                    }
                                }
                                break;

                            case "ipaddress":

                                clientIpV4 = rootChild.InnerText;
                                break;

                            case "ipaddressv6":

                                clientIpV6 = rootChild.InnerText;
                                break;

                            case "port":

                                portServiceName = rootChild.InnerText;
                                break;

                            case "transport":

                                switch (rootChild.InnerText)
                                {
                                    case "dual":

                                        transportType = VPN_PLUGIN_TRANSPORT_TYPE.VPN_PLUGIN_TRANSPORT_TYPE_DUAL;
                                        break;

                                    case "udp":

                                        transportType = VPN_PLUGIN_TRANSPORT_TYPE.VPN_PLUGIN_TRANSPORT_TYPE_UDP;
                                        break;

                                    default:

                                        transportType = VPN_PLUGIN_TRANSPORT_TYPE.VPN_PLUGIN_TRANSPORT_TYPE_TCP;
                                        break;
                                }

                                break;

                            case "maxframesize":

                                try
                                {
                                    maxFrameSize = UInt32.Parse(rootChild.InnerText);
                                }
                                catch (Exception)
                                {
                                    logger.LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, String.Format("Warning: Unable to parse maxFrameSize from Custom Configuration. Default value of {0} will be used.", maxFrameSize));
                                }

                                break;

                            case "customui":

                                foreach (IXmlNode customuiChild in rootChild.ChildNodes)
                                {
                                    switch (customuiChild.NodeName)
                                    {
                                        case "preauth":

                                            foreach (IXmlNode precustomuiChild in customuiChild.ChildNodes)
                                            {
                                                switch (precustomuiChild.NodeName)
                                                {
                                                    case "prompt":

                                                        List<IVpnCustomPrompt> customPrompt = new List<IVpnCustomPrompt>();
                                                        if (ConvertXmlToCustomPrompt(precustomuiChild, out customPrompt))
                                                        {
                                                            preAuthCustomPrompts.Add(customPrompt);
                                                        }

                                                        break;
                                                }
                                            }

                                            break;

                                        case "postauth":

                                            foreach (IXmlNode postcustomuiChild in customuiChild.ChildNodes)
                                            {
                                                switch (postcustomuiChild.NodeName)
                                                {
                                                    case "prompt":

                                                        List<IVpnCustomPrompt> customPrompt = new List<IVpnCustomPrompt>();
                                                        if (ConvertXmlToCustomPrompt(postcustomuiChild, out customPrompt))
                                                        {
                                                            postAuthCustomPrompts.Add(customPrompt);
                                                        }

                                                        break;
                                                }
                                            }

                                            break;
                                    }
                                }

                                break;

                            case "credentials":

                                foreach (IXmlNode credentialsChild in rootChild.ChildNodes)
                                {
                                    switch (credentialsChild.NodeName)
                                    {
                                        case "credential":

                                            VPN_AUTHENTICATION auth = new VPN_AUTHENTICATION();
                                            auth.useSingleSignOn = false;

                                            foreach (IXmlNode credChild in credentialsChild.ChildNodes)
                                            {
                                                switch (credChild.NodeName)
                                                {
                                                    case "type":

                                                        switch (credChild.InnerText)
                                                        {
                                                            case "otp":

                                                                auth.authType = VpnCredentialType.UsernameOtpPin;
                                                                break;

                                                            case "userpasspin":

                                                                auth.authType = VpnCredentialType.UsernamePasswordAndPin;
                                                                break;

                                                            case "passchange":

                                                                auth.authType = VpnCredentialType.UsernamePasswordChange;
                                                                break;

                                                            case "smartcard":

                                                                auth.authType = VpnCredentialType.SmartCard;
                                                                break;

                                                            case "protectedcert":

                                                                auth.authType = VpnCredentialType.ProtectedCertificate;
                                                                break;

                                                            case "unprotectedcert":

                                                                auth.authType = VpnCredentialType.UnProtectedCertificate;
                                                                break;

                                                            default:

                                                                auth.authType = VpnCredentialType.UsernamePassword;
                                                                break;
                                                        }

                                                        break;

                                                    case "user":

                                                        auth.expectedUser = credChild.InnerText;
                                                        break;

                                                    case "pass":

                                                        auth.expectedPass = credChild.InnerText;
                                                        break;

                                                    case "newpass":

                                                        auth.expectedNewPass = credChild.InnerText;
                                                        break;

                                                    case "pin":

                                                        auth.expectedPin = credChild.InnerText;
                                                        break;

                                                    case "certsubject":

                                                        auth.certSubject = credChild.InnerText;
                                                        break;

                                                    case "sso":

                                                        switch (credChild.InnerText)
                                                        {
                                                            case "true":

                                                                auth.useSingleSignOn = true;
                                                                break;
                                                        }

                                                        break;
                                                }
                                            }

                                            authentications.Add(auth);

                                            break;
                                    }
                                }

                                break;

                            case "networksettings":

                                foreach (IXmlNode settingChild in rootChild.ChildNodes)
                                {
                                    switch (settingChild.NodeName)
                                    {
                                        case "routes":

                                            foreach (IXmlNode routesChild in settingChild.ChildNodes)
                                            {
                                                switch (routesChild.NodeName)
                                                {
                                                    case "includev4":

                                                        foreach (IXmlNode includev4Child in routesChild.ChildNodes)
                                                        {
                                                            switch (includev4Child.NodeName)
                                                            {
                                                                case "route":

                                                                    VpnRoute route;
                                                                    if (ConvertXmlToRoute(includev4Child, out route))
                                                                    {
                                                                        ipv4InclusionRoutes.Add(route);
                                                                    }

                                                                    break;
                                                            }
                                                        }

                                                        break;

                                                    case "excludev4":

                                                        foreach (IXmlNode excludev4Child in routesChild.ChildNodes)
                                                        {
                                                            switch (excludev4Child.NodeName)
                                                            {
                                                                case "route":

                                                                    VpnRoute route;
                                                                    if (ConvertXmlToRoute(excludev4Child, out route))
                                                                    {
                                                                        ipv4ExclusionRoutes.Add(route);
                                                                    }

                                                                    break;
                                                            }
                                                        }

                                                        break;

                                                    case "includev6":

                                                        foreach (IXmlNode includev6Child in routesChild.ChildNodes)
                                                        {
                                                            switch (includev6Child.NodeName)
                                                            {
                                                                case "route":

                                                                    VpnRoute route;
                                                                    if (ConvertXmlToRoute(includev6Child, out route))
                                                                    {
                                                                        ipv6InclusionRoutes.Add(route);
                                                                    }

                                                                    break;
                                                            }
                                                        }

                                                        break;

                                                    case "excludev6":

                                                        foreach (IXmlNode excludev6Child in routesChild.ChildNodes)
                                                        {
                                                            switch (excludev6Child.NodeName)
                                                            {
                                                                case "route":

                                                                    VpnRoute route;
                                                                    if (ConvertXmlToRoute(excludev6Child, out route))
                                                                    {
                                                                        ipv6ExclusionRoutes.Add(route);
                                                                    }

                                                                    break;
                                                            }
                                                        }

                                                        break;

                                                    case "excludelocalsubnets":

                                                        switch (routesChild.InnerText)
                                                        {
                                                            case "true":

                                                                excludeLocalSubnets = true;
                                                                break;
                                                        }

                                                        break;
                                                }
                                            }

                                            break;

                                        case "namespaces":

                                            foreach (IXmlNode namespacesChild in settingChild.ChildNodes)
                                            {
                                                switch (namespacesChild.NodeName)
                                                {
                                                    case "proxyautoconfig":
                                                        //v2 Addition
                                                        if (IsV2)
                                                        {
                                                            domainnameAssignment.ProxyAutoConfigurationUri = new Uri(namespacesChild.InnerText);
                                                        }
                                                        else
                                                        {
                                                            namespaceAssignment.ProxyAutoConfigUri = new Uri(namespacesChild.InnerText);
                                                        }
                                                        break;

                                                    case "namespace":

                                                        string space = String.Empty;
                                                        List<HostName> dnsServerList = new List<HostName>();
                                                        List<HostName> proxyServerList = new List<HostName>();

                                                        foreach (IXmlNode namespaceChild in namespacesChild.ChildNodes)
                                                        {
                                                            switch (namespaceChild.NodeName)
                                                            {
                                                                case "space":

                                                                    space = namespaceChild.InnerText;
                                                                    break;

                                                                case "dnsservers":

                                                                    foreach (IXmlNode dnsserversChild in namespaceChild.ChildNodes)
                                                                    {
                                                                        switch (dnsserversChild.NodeName)
                                                                        {
                                                                            case "server":

                                                                                HostName dnsServer = new HostName(dnsserversChild.InnerText);
                                                                                dnsServerList.Add(dnsServer);

                                                                                break;
                                                                        }
                                                                    }

                                                                    break;

                                                                case "proxyservers":

                                                                    foreach (IXmlNode proxyserversChild in namespaceChild.ChildNodes)
                                                                    {
                                                                        switch (proxyserversChild.NodeName)
                                                                        {
                                                                            case "server":

                                                                                HostName proxyServer = new HostName(proxyserversChild.InnerText);
                                                                                proxyServerList.Add(proxyServer);

                                                                                break;
                                                                        }
                                                                    }

                                                                    break;
                                                            }
                                                        }

                                                        // We are expected to pass nullptr instead of empty lists

                                                        if (proxyServerList.Count == 0)
                                                        {
                                                            proxyServerList = null;
                                                        }

                                                        if (dnsServerList.Count == 0)
                                                        {
                                                            dnsServerList = null;
                                                        }

                                                        // Check if we have enough data to add a namespace

                                                        if (!String.IsNullOrEmpty(space))
                                                        {
                                                            //v2 Addition
                                                            if (IsV2)
                                                            {
                                                                VpnDomainNameInfo domainnameInfo = new VpnDomainNameInfo(space, VpnDomainNameType.Suffix, dnsServerList, proxyServerList);
                                                                domainnameList.Add(domainnameInfo);
                                                            }
                                                            else
                                                            {
                                                                VpnNamespaceInfo namespaceInfo = new VpnNamespaceInfo(space, dnsServerList, proxyServerList);
                                                                namespaceList.Add(namespaceInfo);
                                                            }
                                                        }

                                                        break;
                                                }
                                            }

                                            break;
                                    }
                                }

                                break;

                            case "reconnect":

                                foreach (IXmlNode reconChild in rootChild.ChildNodes)
                                {
                                    switch (reconChild.NodeName)
                                    {
                                        case "ipaddress":

                                            clientIpReconnectV4 = reconChild.InnerText;
                                            break;

                                        case "ipaddressv6":

                                            clientIpReconnectV6 = reconChild.InnerText;
                                            break;
                                    }
                                }

                                break;

                            case "loglevel":

                                switch (rootChild.InnerText)
                                {
                                    case "low":

                                        logger.loggingSettings.logLevel = VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW;
                                        break;

                                    case "medium":

                                        logger.loggingSettings.logLevel = VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM;
                                        break;

                                    case "high":

                                        logger.loggingSettings.logLevel = VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_HIGH;
                                        break;

                                    default:

                                        logger.loggingSettings.logLevel = VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_MEDIUM;
                                        break;
                                }

                                break;

                            case "packetcapture":

                                switch (rootChild.InnerText)
                                {
                                    case "true":

                                        logger.loggingSettings.packetCapture = true;
                                        break;
                                }

                                break;

                            case "buffercapture":

                                switch (rootChild.InnerText)
                                {
                                    case "true":

                                        logger.loggingSettings.bufferCapture = true;
                                        break;
                                }

                                break;

                            case "exception":

                                exceptionFlags.exMode = true;

                                foreach (IXmlNode exFuncChild in rootChild.ChildNodes)
                                {
                                    switch (exFuncChild.NodeName)
                                    {
                                        case "func":

                                            switch (exFuncChild.InnerText)
                                            {
                                                case "connect_1":

                                                    exceptionFlags.exConnect_1 = true;
                                                    break;

                                                case "connect_2":

                                                    exceptionFlags.exConnect_2 = true;
                                                    break;

                                                case "connect_3":

                                                    exceptionFlags.exConnect_3 = true;
                                                    break;

                                                case "encapsulate":

                                                    exceptionFlags.exEncapsulate = true;
                                                    break;

                                                case "decapsulate":

                                                    exceptionFlags.exDecapsulate = true;
                                                    break;

                                                case "disconnect":

                                                    exceptionFlags.exDisconnect = true;
                                                    break;
                                            }

                                            break;
                                    }
                                }

                                break;

                            case "testactivateforeground":

                                switch (rootChild.InnerText)
                                {
                                    case "true":

                                        this.TestActivateForeground = true;
                                        break;
                                }

                                break;
                            default:

                                break;
                        }
                    }
                }
                else
                {
                    logger.LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Warning: CustomConfiguration XML schema appears to be invalid. Root element 'pluginschema' was not found.");

                }
            }

            //
            // Check to see if we need to auto-generate a IP address for this client
            // Handle the case in which there is no custom configuration (or we received incomplete/invalid xml schema)
            //
            if ((String.IsNullOrEmpty(clientIpV4) && String.IsNullOrEmpty(clientIpV6)) || clientIpV4 == "auto")
            {
                //
                // If the ip address is specified as "auto" then it is an indication that the plug-in should try to randomize its IP address to avoid collisions
                // with other VPN plug-in's connected to the same server/network. In this case, we still use the default 172.10.10. prefix, but we randomly generate
                // the last octet of the IP address (note that 172.10.10.1 through 172.10.10.15 are reserved for manual testing and will not be randomly picked here).
                // This is by no means perfect and collisions are still possible. A better long term solution will be to have a protocol with the VPN server and to
                // let the server assign the client's address dynamically.
                //
                clientIpV4 = "172.10.10." + GenerateRandomInt(16, 254).ToString();
                //
                // Add a default route to make this connection force tunnel, since we have no other route information available.
                // It should be safe to just add v4 default route, because without CustomConfiguration the plug-in will only assign
                // a V4 client IP anyhow.
                //
                HostName defaultRoute = new HostName("192.168.21.0");
                VpnRoute forceRoute = new VpnRoute(defaultRoute, 24);
                ipv4InclusionRoutes.Add(forceRoute);

                logger.LogMessage(channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, "Warning: This will be a split tunnel configuration (Traffic to 192.168.21.0/24 will go over VPN)");
            }
            else if (String.IsNullOrEmpty(clientIpV6) || clientIpV6 == "auto")
            {
                clientIpV6 = "fe7f::90:" + GenerateRandomInt(16, 254).ToString();
            }

            //
            // If this is a reconnect and we have been given some reconnection settings in the custom configuration
            // then we should apply them now
            //
            if (IsReconnect)
            {
                if (!String.IsNullOrEmpty(clientIpReconnectV4))
                {
                    clientIpV4 = clientIpReconnectV4;
                }

                if (!String.IsNullOrEmpty(clientIpReconnectV6))
                {
                    clientIpV6 = clientIpReconnectV6;
                }
            }

            //
            // Finish assigning any routes or namespaces that were specified via the custom configuration. If the lists
            // are of zero length then we pass nullptr instead of a zero length vector.
            //
            if (ipv4InclusionRoutes.Count == 0 &&
                ipv4ExclusionRoutes.Count == 0 &&
                ipv6InclusionRoutes.Count == 0 &&
                ipv6ExclusionRoutes.Count == 0)
            {
                routeAssignment = null;
            }
            else
            {
                if (ipv4InclusionRoutes.Count > 0)
                {
                    routeAssignment.Ipv4InclusionRoutes = ipv4InclusionRoutes;
                }

                if (ipv4ExclusionRoutes.Count > 0)
                {
                    routeAssignment.Ipv4ExclusionRoutes = ipv4ExclusionRoutes;
                }

                if (ipv6InclusionRoutes.Count > 0)
                {
                    routeAssignment.Ipv6InclusionRoutes = ipv6InclusionRoutes;
                }

                if (ipv6ExclusionRoutes.Count > 0)
                {
                    routeAssignment.Ipv6ExclusionRoutes = ipv6ExclusionRoutes;
                }

                routeAssignment.ExcludeLocalSubnets = excludeLocalSubnets;
            }
            //v2 Addition
            if (IsV2)
            {
                if (domainnameList.Count > 0)
                {
                    foreach (VpnDomainNameInfo info in domainnameList)
                    {
                        domainnameAssignment.DomainNameList.Add(info);
                    }
                }
                else
                {
                    if (domainnameAssignment.ProxyAutoConfigurationUri == null)
                    {
                        domainnameAssignment = null;
                    }
                }
            }
            else
            {
                if (namespaceList.Count > 0)
                {
                    namespaceAssignment.NamespaceList = namespaceList;
                }
                else
                {
                    if (namespaceAssignment.ProxyAutoConfigUri == null)
                    {
                        namespaceAssignment = null;
                    }
                }
            }


            if (String.IsNullOrEmpty(portServiceName))
            {
                //
                // We didn't receive a port via custom configuration, so instead we try to read the port directly from the channel configuration.
                // If that's not set (i.e. we receive port 0) then we use a default port for testing purposes
                //            
                portServiceName = ((cfg.ServerServiceName == "0") ? defaultPort : cfg.ServerServiceName);
            }

            //
            // Output configuration for debugging
            //
            string configOutput = "Plug-in: CSharp\n";
            configOutput += String.Format("Client IP v4: {0}\n", clientIpV4);
            configOutput += String.Format("Client IP v6: {0}\n", clientIpV6);
            configOutput += String.Format("Server Port: {0}\n", portServiceName);
            configOutput += String.Format("Max Frame Size: {0}\n", maxFrameSize.ToString());
            configOutput += String.Format("Socket Protection Level: {0}\n", protectionLevel.ToString());


            if (IsV2)
            {
                configOutput += "<v2>: tag present\n";
                if (trafficFilterAssignment.TrafficFilterList.Count > 0)
                {
                    configOutput += String.Format("appid count: {0}\n", trafficFilterAssignment.TrafficFilterList.Count);
                    foreach (VpnTrafficFilter tf in trafficFilterAssignment.TrafficFilterList)
                    {
                        configOutput += String.Format("Name = {0}, Type = {1}\n", tf.AppId.Value, tf.AppId.Type);
                    }
                }
                else
                {
                    configOutput += "<v2>: No appid specified\n";
                }
            }

            if (authentications.Count > 0)
            {
                configOutput += "Use Credentials: true\n";
                configOutput += String.Format("Number of authentications requested: {0}\n", authentications.Count.ToString());

                foreach (VPN_AUTHENTICATION auth in authentications)
                {
                    configOutput += String.Format("Request authentication type: {0} (SSO: {1})\n", auth.authType.ToString(), (auth.useSingleSignOn ? "true" : "false"));
                }
            }
            else
            {
                configOutput += "Use Credentials: false\n";
            }

            if (preAuthCustomPrompts.Count > 0 || postAuthCustomPrompts.Count > 0)
            {
                configOutput += "Use Custom UI: true\n";
                configOutput += String.Format("Number of Pre-Auth UI prompts requested: {0}\n", preAuthCustomPrompts.Count.ToString());
                configOutput += String.Format("Number of Post-Auth UI prompts requested: {0}\n", postAuthCustomPrompts.Count.ToString());
            }
            else
            {
                configOutput += "Use Custom UI: false\n";
            }

            if (routeAssignment != null)
            {
                configOutput += "Use Routes: true\n";

                if (routeAssignment.Ipv4InclusionRoutes != null)
                {
                    foreach (VpnRoute route in routeAssignment.Ipv4InclusionRoutes)
                    {
                        configOutput += String.Format("Inclusion Route: {0}/{1}\n", route.Address.DisplayName, route.PrefixSize.ToString());
                    }
                }

                if (routeAssignment.Ipv4ExclusionRoutes != null)
                {
                    foreach (VpnRoute route in routeAssignment.Ipv4ExclusionRoutes)
                    {
                        configOutput += String.Format("Exclusion Route: {0}/{1}\n", route.Address.DisplayName, route.PrefixSize.ToString());
                    }
                }

                if (routeAssignment.Ipv6InclusionRoutes != null)
                {
                    foreach (VpnRoute route in routeAssignment.Ipv6InclusionRoutes)
                    {
                        configOutput += String.Format("Inclusion Route: {0}/{1}\n", route.Address.DisplayName, route.PrefixSize.ToString());
                    }
                }

                if (routeAssignment.Ipv6ExclusionRoutes != null)
                {
                    foreach (VpnRoute route in routeAssignment.Ipv6ExclusionRoutes)
                    {
                        configOutput += String.Format("Exclusion Route: {0}/{1}\n", route.Address.DisplayName, route.PrefixSize.ToString());
                    }
                }

                configOutput += String.Format("Exclude Local Subnets: {0}\n", routeAssignment.ExcludeLocalSubnets.ToString());
            }
            else
            {
                configOutput += "Use Routes: false\n";
            }

            //v2 Addition
            if (IsV2)
            {
                if (domainnameAssignment != null)
                {
                    configOutput += "[v2]Use Namespaces: true\n";

                    if (domainnameAssignment.ProxyAutoConfigurationUri != null)
                    {
                        configOutput += String.Format("[v2]Proxy Autoconfig Uri: {0}\n", domainnameAssignment.ProxyAutoConfigurationUri.ToString());
                    }

                    if (domainnameAssignment.DomainNameList != null)
                    {
                        foreach (VpnDomainNameInfo domainnameinfo in domainnameAssignment.DomainNameList)
                        {
                            configOutput += String.Format("[v2]Namespace: {0}\n", domainnameinfo.DomainName);

                            if (domainnameinfo.DnsServers != null)
                            {
                                foreach (HostName dnsServer in domainnameinfo.DnsServers)
                                {
                                    configOutput += String.Format("[v2]DNS Server: {0}\n", dnsServer.DisplayName);
                                }
                            }

                            if (domainnameinfo.WebProxyServers != null)
                            {
                                foreach (HostName proxy in domainnameinfo.WebProxyServers)
                                {
                                    configOutput += String.Format("[v2]Proxy Server: {0}\n", proxy.DisplayName);
                                }
                            }
                        }
                    }
                }
                else
                {
                    configOutput += "[v2]Use Namespaces: false\n";
                }

            }
            else
            {
                if (namespaceAssignment != null)
                {
                    configOutput += "Use Namespaces: true\n";

                    if (namespaceAssignment.ProxyAutoConfigUri != null)
                    {
                        configOutput += String.Format("Proxy Autoconfig Uri: {0}\n", namespaceAssignment.ProxyAutoConfigUri.ToString());
                    }

                    if (namespaceAssignment.NamespaceList != null)
                    {
                        foreach (VpnNamespaceInfo namespaceInfo in namespaceAssignment.NamespaceList)
                        {
                            configOutput += String.Format("Namespace: {0}\n", namespaceInfo.Namespace);

                            if (namespaceInfo.DnsServers != null)
                            {
                                foreach (HostName dnsServer in namespaceInfo.DnsServers)
                                {
                                    configOutput += String.Format("DNS Server: {0}\n", dnsServer.DisplayName);
                                }
                            }

                            if (namespaceInfo.WebProxyServers != null)
                            {
                                foreach (HostName proxy in namespaceInfo.WebProxyServers)
                                {
                                    configOutput += String.Format("Proxy Server: {0}\n", proxy.DisplayName);
                                }
                            }
                        }
                    }
                }
                else
                {
                    configOutput += "Use Namespaces: false\n";
                }
            }

            configOutput += String.Format("Test Activate foreground: {0} \n", this.TestActivateForeground);
           
            
            logger.LogMessage(this.channel, VPN_PLUGIN_LOG_LEVEL.VPN_PLUGIN_LOG_LEVEL_LOW, configOutput);

            // 
            // END: Custom Configuration parsing
            //
        }

        /// <summary>
        /// Converts a XMl representation of a Custom UI prompt into a list of IVpnCustomPrompt objects
        /// </summary>
        /// <param name="promptXml">Custom configuration XML representing the Custom UI to create</param>
        /// <param name="customPrompt">Resultant list of IVpnCustomPrompt objects to return</param>
        /// <returns>bool</returns>
        private bool ConvertXmlToCustomPrompt(IXmlNode promptXml, out List<IVpnCustomPrompt> customPrompt)
        {
            customPrompt = new List<IVpnCustomPrompt>();

            foreach (IXmlNode promptChild in promptXml.ChildNodes)
            {
                switch (promptChild.NodeName)
                {
                    case "editbox":

                        VpnCustomEditBox editBox = new VpnCustomEditBox();

                        foreach (IXmlNode editboxChild in promptChild.ChildNodes)
                        {
                            switch (editboxChild.NodeName)
                            {
                                case "label":

                                    editBox.Label = editboxChild.InnerText;
                                    break;

                                case "defaulttext":

                                    editBox.DefaultText = editboxChild.InnerText;
                                    break;

                                case "compulsory":

                                    switch (editboxChild.InnerText)
                                    {
                                        case "true":

                                            editBox.Compulsory = true;
                                            break;

                                        case "false":

                                            editBox.Compulsory = false;
                                            break;
                                    }

                                    break;

                                case "noecho":

                                    switch (editboxChild.InnerText)
                                    {
                                        case "true":

                                            editBox.NoEcho = true;
                                            break;

                                        case "false":

                                            editBox.NoEcho = false;
                                            break;
                                    }

                                    break;

                                case "bordered":

                                    switch (editboxChild.InnerText)
                                    {
                                        case "true":

                                            editBox.Bordered = true;
                                            break;

                                        case "false":

                                            editBox.Bordered = false;
                                            break;
                                    }

                                    break;
                            }
                        }

                        customPrompt.Add(editBox);

                        break;

                    case "combobox":

                        VpnCustomComboBox comboBox = new VpnCustomComboBox();

                        foreach (IXmlNode comboboxChild in promptChild.ChildNodes)
                        {
                            switch (comboboxChild.NodeName)
                            {
                                case "label":

                                    comboBox.Label = comboboxChild.InnerText;
                                    break;

                                case "compulsory":

                                    switch (comboboxChild.InnerText)
                                    {
                                        case "true":

                                            comboBox.Compulsory = true;
                                            break;

                                        case "false":

                                            comboBox.Compulsory = false;
                                            break;
                                    }

                                    break;

                                case "bordered":

                                    switch (comboboxChild.InnerText)
                                    {
                                        case "true":

                                            comboBox.Bordered = true;
                                            break;

                                        case "false":

                                            comboBox.Bordered = false;
                                            break;
                                    }

                                    break;

                                case "options":

                                    List<string> options = new List<string>();

                                    foreach (IXmlNode optionsChild in comboboxChild.ChildNodes)
                                    {
                                        switch (optionsChild.NodeName)
                                        {
                                            case "option":

                                                options.Add(optionsChild.InnerText);
                                                break;
                                        }
                                    }

                                    if (options.Count > 0)
                                    {
                                        comboBox.OptionsText = options;
                                    }

                                    break;
                            }
                        }

                        customPrompt.Add(comboBox);

                        break;

                    case "textbox":

                        VpnCustomTextBox textBox = new VpnCustomTextBox();

                        foreach (IXmlNode textboxChild in promptChild.ChildNodes)
                        {
                            switch (textboxChild.NodeName)
                            {
                                case "label":

                                    textBox.Label = textboxChild.InnerText;
                                    break;

                                case "text":

                                    textBox.DisplayText = textboxChild.InnerText;
                                    break;

                                case "compulsory":

                                    switch (textboxChild.InnerText)
                                    {
                                        case "true":

                                            textBox.Compulsory = true;
                                            break;

                                        case "false":

                                            textBox.Compulsory = false;
                                            break;
                                    }

                                    break;

                                case "bordered":

                                    switch (textboxChild.InnerText)
                                    {
                                        case "true":

                                            textBox.Bordered = true;
                                            break;

                                        case "false":

                                            textBox.Bordered = false;
                                            break;
                                    }

                                    break;
                            }
                        }

                        customPrompt.Add(textBox);

                        break;

                    case "checkbox":

                        VpnCustomCheckBox checkBox = new VpnCustomCheckBox();

                        foreach (IXmlNode checkboxChild in promptChild.ChildNodes)
                        {
                            switch (checkboxChild.NodeName)
                            {
                                case "label":

                                    checkBox.Label = checkboxChild.InnerText;
                                    break;

                                case "checked":

                                    switch (checkboxChild.InnerText)
                                    {
                                        case "true":

                                            checkBox.InitialCheckState = true;
                                            break;

                                        case "false":

                                            checkBox.InitialCheckState = false;
                                            break;
                                    }

                                    break;

                                case "compulsory":

                                    switch (checkboxChild.InnerText)
                                    {
                                        case "true":

                                            checkBox.Compulsory = true;
                                            break;

                                        case "false":

                                            checkBox.Compulsory = false;
                                            break;
                                    }

                                    break;

                                case "bordered":

                                    switch (checkboxChild.InnerText)
                                    {
                                        case "true":

                                            checkBox.Bordered = true;
                                            break;

                                        case "false":

                                            checkBox.Bordered = false;
                                            break;
                                    }

                                    break;
                            }
                        }

                        customPrompt.Add(checkBox);

                        break;

                    case "errorbox":

                        VpnCustomErrorBox errorBox = new VpnCustomErrorBox();

                        foreach (IXmlNode errorboxChild in promptChild.ChildNodes)
                        {
                            switch (errorboxChild.NodeName)
                            {
                                case "label":

                                    errorBox.Label = errorboxChild.InnerText;
                                    break;

                                case "bordered":

                                    switch (errorboxChild.InnerText)
                                    {
                                        case "true":

                                            errorBox.Bordered = true;
                                            break;

                                        case "false":

                                            errorBox.Bordered = false;
                                            break;
                                    }

                                    break;
                            }
                        }

                        customPrompt.Add(errorBox);

                        break;
                }
            }

            //
            // We're done building up this prompt, as long as it ended up containing at least one UI element
            // we can return success
            //
            if (customPrompt.Count > 0)
            {
                return true;
            }

            return false;
        }

        /// <summary>
        /// Converts a XMl representation of a route into a VpnRoute object
        /// </summary>
        /// <param name="routeXml">Custom configuration XML representing a route</param>
        /// <param name="route">Resultant VpnRoute object to return</param>
        /// <returns>bool</returns>
        private bool ConvertXmlToRoute(IXmlNode routeXml, out VpnRoute route)
        {
            bool retVal = false;
            route = null;

            //
            // Create the objects necessary to represent each requested Route
            // and then populate the objects using the values from the XML
            //
            HostName routeAddress = null;
            byte prefixSize = 0;

            foreach (IXmlNode routeChild in routeXml.ChildNodes)
            {
                switch (routeChild.NodeName)
                {
                    case "address":

                        routeAddress = new HostName(routeChild.InnerText);
                        break;

                    case "prefix":

                        if (!Byte.TryParse(routeChild.InnerText, out prefixSize))
                        {
                            prefixSize = 0;
                        }
                        break;
                }
            }

            //
            // Only add the route if we have an address
            //
            if (routeAddress != null &&
                !String.IsNullOrEmpty(routeAddress.DisplayName))
            {
                route = new VpnRoute(routeAddress, prefixSize);
                retVal = true;
            }

            return retVal;
        }

        /// <summary>
        /// Generate a random int between 1 and max
        /// </summary>
        /// <param name="max">Max number to generate</param>
        /// <returns>int</returns>
        private int GenerateRandomInt(int min, int max)
        {
            Random rnd = new Random();
            return rnd.Next(min, max);
        }
    }
}
