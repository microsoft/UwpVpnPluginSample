---
page_type: sample
languages:
- csharp
products:
- dotnet
description: "UWP VPN sample code demonstrates creating a plugin-style VPN app"
urlFragment: "update-this-to-unique-url-stub"
---

# Official Microsoft UWP VPN Sample

Sample code for the Universal Windows Platform (UWP) Virtual Private Network (VPN) plugin API. The VPN Plugin API lets developers create new VPN apps that use otherwise-unsupported VPN encryption algorithmns. The VPN apps in Windows are curated: VPN apps will need the "networkingVpnProvider" restricted capability.


## Contents

Outline the file contents of the repository. It helps users navigate the codebase, build configuration and any related assets.

| File/folder           | Description                                |
|-----------------------|--------------------------------------------|
| `CSharp`              | Sample C# source code.                     |
| `CppWinRT`                 | Sample C++ source code.                    |
| `SimpleVpnServer`     | Debugging and validation VPN server.       |
| `SimpleUdpListener`     | UDP listener that can receive packets from the VPN client.       |
| `.gitignore`          | Define what to ignore at commit time.      |
| `CODE_OF_CONDUCT.md`  | Expectations for people participating in this repo. |
| `LICENSE`             | The license for the sample.                |
| `README.md`           | This README file.                          |
| `SECURITY.md`         | Security aspects of the sample.            |

## Prerequisites

This sample works with Visual Studio 2019 (or later) and Windows 11. You will need a copy of a matching Platform SDK.

## Setting up and running the sample

To run the sample, you'll need two computers: one to run the SimpleVpnServer and the other to run the client code. 

* On the "server" computer, compile and run the server.
* Note the server's IP address.
* On your main development computer, compile and run the client (either C# or C++). When you do, you'll be asked for the server IP address.

In Windows 11, the VPN UI is connected to the Quick Actions menu. The user may have to use the 'Edit' feature to add VPN UI.

## Code organization

## Code organization by directory

The VPN UWP sample code is divided into a server and two clients, one for C# and the other for C++. The C# code is often best for studying how the the UWP VPN platform APIs work together to create a full VPN client solution.

| Directory | Contents |
|-----|-----|
| SimpleVpnServer | C# code for a simple VPN server. The "protocol" is a custom protocol designed to be trivial to implement and debug |
| SimpleUdpListener | C# code for a simple UDP listener. The listener sends back whatever payload it receives. Useful with the "send udp packet/stream" from UWP client |
| CSharp/TestVpnPluginApp | Foreground UI code for the VPN client |
| CSharp/TestVpnPluginAppBg | Background VPN UWP code for the VPN client; handles creating sockets to the server and encapsulation/decapsulation of VPN packets |
| CppWinRT | Demonstration of writing C++ code for VPN; the code matches the C# structure. |

## Code organization by feature

The UWP VPN Platform supports all of the features needed to build a complete VPN client solution.

| Feature | Location in code
|-----|-----|
| System Tray | VPN client is automatically visible in the system tray. The user may need to manually add the VPN widget. |
| Custom XML configuration |  TestVpnPluginAppBg/CustomConfiguration.cs parses custom XML that can be configured from Intune or other MDM management servers. |
| Configure network routes | Routes are passed into StartWithTrafficFilter. |
| Send/Receive packets | Network buffers are handed to the TestVpnPluginAppBg/VpnPlugin.cs **Encapsulate** and **Decapsulate** method and then handed to a seperate thread. |
| Start web authentication | TestVpnPluginAppBg/VpnPlugn.cs in the **Connect** method with the call to channel.ActivateForeground to call into the UX app. |
| Handle web authentication | TestVpnPluginApp/App.cs **OnActivated** is called when activated with type VpnForegroundActivatedEventArgs. |
| Connect socket to server | TestVpnPluginAppBg/VpnPlugin.cs in the **Connect** method.  |

The Windows UWP VPN platform handles all aspects of creating a virtual network adapter and adding it to the system along with appropriate metrics and Name Resolution Policy8 Table (NRPT) entries, DNS servers, and more.

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
