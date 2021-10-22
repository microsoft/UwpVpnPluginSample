using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.MemoryMappedFiles;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Timers;
using TestVpnPluginApp.Common;
using TestVpnPluginAppBg;
using Windows.ApplicationModel;
using Windows.Networking.Vpn;
using Windows.UI.Core;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
// The Basic Page item template is documented at http://go.microsoft.com/fwlink/?LinkId=234237

namespace TestVpnPluginApp
{
    /// <summary>
    /// A basic page that provides characteristics common to most applications.
    /// </summary>
    public sealed partial class MainPage : Page
    {
        private const string PROFILE_NAME = "Test VPN Plugin Autoprofile";
        private const string MAPPED_MEMORY_NAME = "PacketCounter";
        private  string packageName = Package.Current.Id.FamilyName;

        private VpnManagementAgent agent = new VpnManagementAgent();
        private ObservableDictionary defaultViewModel = new ObservableDictionary();
        private System.Timers.Timer timer;
        /// <summary>
        /// This can be changed to a strongly typed view model.
        /// </summary>
        public ObservableDictionary DefaultViewModel
        {
            get { return defaultViewModel; }
        }


        private async Task LogAsync(string text)
        {
            Debug.WriteLine(text);
            await Dispatcher.RunAsync(CoreDispatcherPriority.Normal, () =>
            {
                Logging.Text += text + "\n";
            });
        }
        private void Log(string text)
        {
            Debug.WriteLine(text);
            Logging.Text += text + "\n";
        }

        /// <summary>
        /// Returns a list of all profiles matching profiles. There can be zero, one or more. 
        /// </summary>
        /// <returns>All profiles which have the right package name; is never null.</returns>
        private async Task<IList<VpnPlugInProfile>> GetMatchingProfilesAsync()
        {
            // In this file, GetProfilesAsync is only called here. Everything else should use the
            // results of this call.
            var list = await agent.GetProfilesAsync();
            IList<VpnPlugInProfile> retval = new List<VpnPlugInProfile>();
            foreach (var profile in list)
            {
                var pluginProfile = profile as VpnPlugInProfile;
                if (pluginProfile?.VpnPluginPackageFamilyName == packageName)
                {
                    retval.Add(pluginProfile);
                }
            }
            return retval;
        }

        /// <summary>
        /// Returns the first connected profile with the correct VpnPluginPackageFamilyName. There should be zero or one of these at all times.
        /// </summary>
        /// <returns></returns>
        private async Task<VpnPlugInProfile> GetFirstConnectedProfileAsync()
        {
            var list = await GetMatchingProfilesAsync();
            foreach (var pluginProfile in list)
            {
                if (pluginProfile.ConnectionStatus == VpnManagementConnectionStatus.Connected
                    || pluginProfile.ConnectionStatus == VpnManagementConnectionStatus.Connecting)
                {
                    return pluginProfile;
                }
            }
            return null;
        }

        /// <summary>
        /// Returns a list of all profiles which can be connected. There might be zero, one, or more return values. 
        /// </summary>
        /// <returns>All profiles which can be connected; is never null.</returns>
        private async Task<IList<VpnPlugInProfile>> GetConnectableProfilesAsync()
        {
            var list = await GetMatchingProfilesAsync();
            var retval = new List<VpnPlugInProfile>();
            foreach (var pluginProfile in list)
            {
                if (pluginProfile.ConnectionStatus == VpnManagementConnectionStatus.Disconnected)
                {
                    retval.Add (pluginProfile);
                }
            }
            return retval;
        }



        /// <summary>
        /// Delete all matching profiles with the given profile name. This is often zero or one. If can be more than one if the user creates a profile with the built-in name
        /// </summary>
        /// <param name="profileName">Name of profile to delete; is generally PROFILE_NAME</param>
        private async Task DeleteExistingProfile(string profileName)
        {
            var list = await GetMatchingProfilesAsync();
            foreach (var profile in list)
            {
                if (profile.ProfileName == profileName)
                {
                    await agent.DisconnectProfileAsync(profile);
                    await agent.DeleteProfileAsync(profile);
                }
            }
        }

        private async Task CreateAppProfile()
        {
            Log($"Creating profile {PROFILE_NAME}");
            await DeleteExistingProfile(PROFILE_NAME);
            // Hard coding parameters for the profile
            VpnPlugInProfile profile = new VpnPlugInProfile();
            profile.RequireVpnClientAppUI = true;
            profile.ProfileName = PROFILE_NAME;
            profile.VpnPluginPackageFamilyName = packageName;
            profile.CustomConfiguration =
@"<pluginschema>
    <testactivateforeground>true</testactivateforeground>
    <port>444</port>
    <ipAddress>10.0.1.2</ipAddress>
    <transport>tcp</transport>
    <loglevel>high</loglevel>
    <packetcapture>true</packetcapture>
    <buffercapture>true</buffercapture>
    <networksettings>
        <routes>
            <includev4>
                <route>
                    <address>192.168.21.0</address>
                    <prefix>24</prefix>
                </route>
            </includev4>
         </routes>
    </networksettings>
</pluginschema>";

            profile.ServerUris.Add(new Uri("http://10.137.192.135"));
            var returnedStatus = await agent.AddProfileFromObjectAsync(profile);
            if (returnedStatus == VpnManagementErrorStatus.Ok)
            {
                Log($"Created new profile {PROFILE_NAME}");
            }
            else
            {
                Log($"Error: unable to create new profile. Reason code is {returnedStatus}");
            }
        }

        private async void SendUDPPacketOnClick(object sender, RoutedEventArgs e)
        {
            await SendUDPPacket();
        }
        private async Task SendUDPPacket()
        {
            try
            {
                using (var client = new UdpClient())
                {
                    client.Client.ReceiveTimeout = 2000;

                    String[] address = udpIP.Text.Split(":");

                    int sendPort = Int32.Parse(address[1]);
                    IPEndPoint ep = new IPEndPoint(IPAddress.Parse(address[0]), sendPort);

                    client.Connect(ep);

                    byte[] data = Encoding.ASCII.GetBytes("Hello World");
                    client.Send(data, data.Length);
                    await LogAsync($"Sent to {ep} now we wait for response");

                    IPEndPoint listenEndPoint = new IPEndPoint(IPAddress.Any, sendPort);
                    byte[] receivedData = client.Receive(ref listenEndPoint);


                    await Dispatcher.RunAsync(CoreDispatcherPriority.Normal, () =>
                    {
                        Log($"Received broadcast message from client {listenEndPoint}");
                        Log($"Decoded data is: {Encoding.UTF8.GetString(receivedData)}");
                        UDPResponse.Text = "response received from: " + listenEndPoint.ToString();
                    });
                }
            }
            catch (Exception ex)
            {
                String errorString = ex.ToString();

                if (ex is SocketException)
                {
                    if ((ex as SocketException).SocketErrorCode == SocketError.TimedOut)
                    {
                        errorString = "No response within 2 seconds";
                    }

                }

                if (ex is IndexOutOfRangeException)
                {
                    errorString = "You are probably missing a : for your port\n" + errorString;
                }
                await Dispatcher.RunAsync(CoreDispatcherPriority.Normal, () =>
                {
                    UDPResponse.Text = errorString;
                    Log(errorString);
                });
            }
        }

        public MainPage()
        {
            InitializeComponent();

            SetTimer();
        }

        private async void CreateAppProfileOnClick(object sender, RoutedEventArgs e)
        {
            await CreateAppProfile();
        }

        private void SetTimer()
        {
            timer = new System.Timers.Timer(500);

            timer.Elapsed += UpdateTextBlocks;
            timer.AutoReset = true;
            timer.Enabled = true;

        }

        public async void UpdateTextBlocks(Object source, ElapsedEventArgs e)
        {
            timer.Enabled = false;
            try
            {
                var list = await GetMatchingProfilesAsync();

                String statusString = "";
                bool isConnectable = false;
                bool isDisconnectable = false;
                VpnPlugInProfile connectedProfile = null;

                list = list.OrderBy(profile => profile.ProfileName).ToList();

                foreach (var profile in list)
                {
                    VpnManagementConnectionStatus status = profile.ConnectionStatus;
                    switch (status)
                    {
                        case VpnManagementConnectionStatus.Connected:
                            statusString += $"Connected to {profile.ProfileName}\n";
                            connectedProfile = profile;
                            isDisconnectable = true;
                            break;
                        case VpnManagementConnectionStatus.Connecting:
                            statusString += $"Connecting to {profile.ProfileName}\n";
                            break;
                        case VpnManagementConnectionStatus.Disconnecting:
                            statusString += $"Disconnecting from {profile.ProfileName}\n";
                            break;
                        case VpnManagementConnectionStatus.Disconnected:
                            statusString += $"Disconnected from {profile.ProfileName}\n";
                            isConnectable = true;
                            break;
                    }
                }
                if (statusString == "")
                {
                    statusString = "No profile found";
                }

                await Dispatcher.RunAsync(CoreDispatcherPriority.Normal, () =>
                {
                    Status.Text = statusString.Trim('\n');
                    ConnectButton.IsEnabled = isConnectable;
                    DisconnectButton.IsEnabled = isDisconnectable;
                });

                if (connectedProfile != null)
                {
                    PACKET_COUNTER counter = new PACKET_COUNTER();
                    int size = Marshal.SizeOf(counter);

                    MemoryMappedFile packetCountMemory = MemoryMappedFile.CreateOrOpen(MAPPED_MEMORY_NAME, size);

                    using (var accessor = packetCountMemory.CreateViewAccessor(0, size))
                    {
                        accessor.Read(0, out counter);
                    }
                    await Dispatcher.RunAsync(CoreDispatcherPriority.Normal, () =>
                    {
                    //PacketCounter.Text = packetCounter;
                    TotalPacketsSent.Text = counter.TotalSent.ToString();
                        TotalUDPSent.Text = counter.TotalUDPSent.ToString();
                        TotalControlSent.Text = counter.TotalUDPSent.ToString();
                        TotalKeepAliveSent.Text = counter.TotalKeepAliveSent.ToString();
                        TotalBytesSent.Text = counter.TotalBytesSent.ToString();
                        TotalPacketsReceived.Text = counter.TotalReceived.ToString();
                        TotalControlReceived.Text = counter.TotalControlReceived.ToString();
                        TotalBytesReceived.Text = counter.TotalBytesReceived.ToString();
                    });
                }
                else
                {
                    await Dispatcher.RunAsync(CoreDispatcherPriority.Normal, () =>
                    {
                        TotalPacketsSent.Text = "N/A";
                        TotalUDPSent.Text = "N/A";
                        TotalControlSent.Text = "N/A";
                        TotalKeepAliveSent.Text = "N/A";
                        TotalBytesSent.Text = "N/A";
                        TotalPacketsReceived.Text = "N/A";
                        TotalControlReceived.Text = "N/A";
                        TotalBytesReceived.Text = "N/A";
                    });
                }
            }
            catch (Exception)
            {

            }
            timer.Enabled = true;
        }


        private async void ToggleUDPStreamOnClick(object sender, RoutedEventArgs e)
        {
            if (doUdpStream)
            {
                Log("Endings stream...");
                await Dispatcher.RunAsync(CoreDispatcherPriority.Normal, () =>
                {
                    streamButton.Content = "Start UDP stream";
                    streamButton.IsEnabled = false;
                });
                doUdpStream = false;
            }
            else
            {
                Log("Starting stream...");
                await Dispatcher.RunAsync(CoreDispatcherPriority.Normal, () =>
                {
                    streamButton.Content = "End UDP stream";
                    streamButton.IsEnabled = true;
                });
                doUdpStream = true;
                startUdpStream();
            }
        }

        bool doUdpStream = false;

        private async void startUdpStream()
        {
            int i = 0;
            while (doUdpStream)
            {
                try
                {
                    using (var client = new UdpClient())
                    {
                        client.Client.ReceiveTimeout = 2000;

                        String[] address = null;
                        await Dispatcher.RunAsync(CoreDispatcherPriority.Normal, () =>
                        {
                            address = udpStreamIP.Text.Split(":");
                        });
                         

                        int sendPort = Int32.Parse(address[1]);
                        IPEndPoint ep = new IPEndPoint(IPAddress.Parse(address[0]), sendPort);

                        client.Connect(ep);

                        byte[] data = Encoding.ASCII.GetBytes("Hello World");
                        client.Send(data, data.Length);
                        await LogAsync($"Sent to {ep} now we wait for response");
                        IPEndPoint listenEndPoint = new IPEndPoint(IPAddress.Any, sendPort);
                        byte[] receivedData = client.Receive(ref listenEndPoint);


                        await Dispatcher.RunAsync(CoreDispatcherPriority.Normal, () =>
                        {
                            Log($"Received broadcast message from client {listenEndPoint}");
                            UDPStreamResponse.Text = i +" responses received from: " + listenEndPoint.ToString();
                        });
                        i++;
                    }
                }
                catch (Exception ex)
                {
                    
                    String errorString = ex.ToString();

                    if (ex is SocketException)
                    {
                        if ((ex as SocketException).SocketErrorCode == SocketError.TimedOut)
                        {
                            errorString = "No response within 2 seconds";
                        }

                    }

                    if (ex is IndexOutOfRangeException)
                    {
                        errorString = "You are probably missing a : for your port\n" + errorString;
                    }
                    await Dispatcher.RunAsync(CoreDispatcherPriority.Normal, () =>
                    {
                        streamButton.Content = "Start UDP stream";
                        streamButton.IsEnabled = false;
                        UDPStreamResponse.Text = errorString;
                        Log(errorString);
                    });
                    doUdpStream = false;
                }
            }

            await Dispatcher.RunAsync(CoreDispatcherPriority.Normal, () =>
            {
                streamButton.IsEnabled = true;
            });
        }



        private async void ConnectOnClick(object sender, RoutedEventArgs e)
        {
            Log($"Attempting to connect.");
            var list = await GetConnectableProfilesAsync();
            var pluginProfile = list.FirstOrDefault();
            if (list.Count > 1)
            {
                // Ask the user to pick a profile.
                // This code demonstrates how to make a simple dialog box in code
                // and let the user select a single item.
                var lv = new ListView()
                {
                    Header = "Unconnected Profiles",
                    SelectionMode = ListViewSelectionMode.Single,
                };
                foreach (var profile in list)
                {
                    var tb = new TextBlock() { Text = profile.ProfileName, Tag = profile };
                    lv.Items.Add(tb);
                }
                lv.SelectedIndex = 0;
                var cd = new ContentDialog()
                {
                    Title = "Select profile to connect",
                    PrimaryButtonText = "Connect",
                    SecondaryButtonText = "Cancel",
                    Content = lv,
                };
                var command = await cd.ShowAsync();
                pluginProfile = null;
                switch (command)
                {
                    case ContentDialogResult.Primary:
                        pluginProfile = (lv.SelectedItem as FrameworkElement).Tag as VpnPlugInProfile;
                        break;
                }
            }

            if (pluginProfile != null)
            {
                Log($"Profile current connection status code starts as {pluginProfile.ConnectionStatus}");
                if (pluginProfile.ConnectionStatus == VpnManagementConnectionStatus.Disconnected)
                {
                    var connectStatus = await agent.ConnectProfileAsync(pluginProfile);
                    if (connectStatus == VpnManagementErrorStatus.Ok)
                    {
                        Log($"Profile connected OK");
                    }
                    else
                    {
                        Log($"ERROR: Unable to connect profile. Connection error status code is {connectStatus}");
                    }
                }
            }
            else
            {
                Log($"ERROR: no such profile {PROFILE_NAME}");
            }
        }

        private async void DisconnectOnClick(object sender, RoutedEventArgs e)
        {
            Log($"Attempting to disconnect.");
            var pluginProfile = await GetFirstConnectedProfileAsync();
            if (pluginProfile != null)
            {
                Log($"Profile current connection status code starts as {pluginProfile.ConnectionStatus}");
                if (pluginProfile.ConnectionStatus == VpnManagementConnectionStatus.Connected)
                {
                    var connectStatus = await agent.DisconnectProfileAsync(pluginProfile);
                    if (connectStatus == VpnManagementErrorStatus.Ok)
                    {
                        Log($"Profile disconnected OK");
                    }
                    else
                    {
                        Log($"ERROR: Unable to disconnect profile. Connection status code is {connectStatus}");
                    }
                }
            }
            else
            {
                Log($"ERROR: no such profile {PROFILE_NAME}");
            }
        }
    }
}
