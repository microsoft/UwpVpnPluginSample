#pragma once
#include "TestVpnPluginAppBgTask.g.h"

using namespace winrt;
using namespace winrt::Windows::Networking::Vpn;
using namespace winrt::Windows::ApplicationModel;
using namespace Background;
using namespace Core;
using namespace winrt::Windows::Foundation;
using namespace winrt::Windows::System;
using namespace winrt::Windows::UI::Core;


namespace winrt::TestVpnPluginAppBg::implementation
{
    struct TestVpnPluginAppBgTask : TestVpnPluginAppBgTaskT<TestVpnPluginAppBgTask>
    {
        TestVpnPluginAppBgTask() = default;

        void Run(Windows::ApplicationModel::Background::IBackgroundTaskInstance const& taskInstance);
    };
}
namespace winrt::TestVpnPluginAppBg::factory_implementation
{
    struct TestVpnPluginAppBgTask : TestVpnPluginAppBgTaskT<TestVpnPluginAppBgTask, implementation::TestVpnPluginAppBgTask>
    {
    };
}