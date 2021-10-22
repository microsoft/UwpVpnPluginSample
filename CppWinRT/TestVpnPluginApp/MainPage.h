#pragma once

#include "MainPage.g.h"

namespace winrt::TestVpnPluginApp::implementation
{
    struct MainPage : MainPageT<MainPage>
    {
        MainPage();
        hstring PROFILE_NAME = L"CPP Test VPN Plugin Autoprofile";

        winrt::Windows::Networking::Vpn::VpnManagementAgent VpnAgent() const
        {
            return m_VpnAgent;
        }

        Windows::Foundation::IAsyncAction CreateAppProfileOnClick(IInspectable, winrt::Windows::UI::Xaml::RoutedEventArgs);
        Windows::Foundation::IAsyncAction CreateProfileHandler();
        Windows::Foundation::IAsyncAction MainPage::DeleteExistingProfile(hstring profileName);

    private:
        winrt::Windows::Networking::Vpn::VpnManagementAgent m_VpnAgent;
    };
}

namespace winrt::TestVpnPluginApp::factory_implementation
{
    struct MainPage : MainPageT<MainPage, implementation::MainPage>
    {
    };
}
