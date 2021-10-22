#include "pch.h"
#include "MainPage.h"
#include "MainPage.g.cpp"

using namespace winrt;
using namespace winrt::Windows::Networking;
using namespace winrt::Windows::Networking::Vpn;
using namespace Windows::UI::Xaml;
using namespace winrt::Windows::Foundation;

using namespace winrt::Windows::ApplicationModel;

namespace winrt::TestVpnPluginApp::implementation
{
    MainPage::MainPage()
    {
        InitializeComponent();
    }

    Windows::Foundation::IAsyncAction MainPage::CreateAppProfileOnClick(IInspectable, RoutedEventArgs)
    {
        co_await CreateProfileHandler();
    }

    Windows::Foundation::IAsyncAction MainPage::DeleteExistingProfile(hstring profileName)
    {
        ::IVpnProfile profile{ nullptr };
        auto vpnProfiles = co_await VpnAgent().GetProfilesAsync();
        bool connected = false;
        for (auto const& vpnProfile : vpnProfiles)
        {
            auto pluginProfile = vpnProfile.try_as<VpnPlugInProfile>();
            if ((pluginProfile != nullptr) &&
                (pluginProfile.ProfileName() == profileName))
            {
                connected = (pluginProfile.ConnectionStatus() == VpnManagementConnectionStatus::Connected) || (pluginProfile.ConnectionStatus() == VpnManagementConnectionStatus::Connecting);
                profile = vpnProfile;
                break;
            }
        }

        if (connected)
        {
            co_await VpnAgent().DisconnectProfileAsync(profile);
        }
        co_await VpnAgent().DeleteProfileAsync(profile);
    }

    Windows::Foundation::IAsyncAction MainPage::CreateProfileHandler()
    {
        co_await DeleteExistingProfile(PROFILE_NAME);
        VpnPlugInProfile profile;
        profile.ProfileName(PROFILE_NAME);
        profile.RequireVpnClientAppUI(true);
        profile.VpnPluginPackageFamilyName(Package::Current().Id().FamilyName());
        auto uri = Uri(L"http://192.168.1.217");
        profile.ServerUris().Append(uri);
        profile.CustomConfiguration(L"<pluginschema><port>444</port><ipAddress>10.0.1.2</ipAddress><transport>tcp</transport><loglevel>high</loglevel><packetcapture>true</packetcapture><buffercapture>true</buffercapture><networksettings><routes><includev4><route><address>192.168.21.0</address><prefix>24</prefix></route></includev4></routes></networksettings></pluginschema>");
        
        auto returnedStatus = co_await VpnAgent().AddProfileFromObjectAsync(profile);
        if (returnedStatus == VpnManagementErrorStatus::Ok)
        {
            //Log("Created new profile {PROFILE_NAME}");
        }
        else
        {
            //Log("Error: unable to create new profile. Reason code is {returnedStatus}");
        }
    }
}
