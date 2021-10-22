#include "pch.h"
#include "TestVpnPluginAppBgTask.h"
#include "TestVpnPluginAppBgTask.g.cpp"
#include "VpnPlugInImpl.h"


namespace winrt::TestVpnPluginAppBg::implementation
{
    void TestVpnPluginAppBgTask::Run(Windows::ApplicationModel::Background::IBackgroundTaskInstance const& taskInstance)
    {
        // Deferral is used within the background task to keep the host process from being suspended or terminated while the task is running
        BackgroundTaskDeferral deferralObj(nullptr);
        static const winrt::hstring PluginName = L"TestVpnPlugin";

        try
        {
            // To keep the host process from being suspended or terminated while the background task is running
            deferralObj = taskInstance.GetDeferral();
            IVpnPlugIn plugin;
            const auto appProperties = CoreApplication::Properties();

            // First we need to look in the property bag to see if we already have an instantiated plug-in object from a previous invocation
            // of this task. It's important to ensure that we use the same instance of our plug-in each time this background task is
            // invoked, as the plug-in may have some internal state that needs to be maintained (e.g. partially decapsulated packets)
            if (appProperties.HasKey(PluginName))
            {
                //
                // We already have a plug-in instance (instantiated during a previous call to this Run method) so we can retrieve it
                //
                auto pluginResult = (appProperties.Lookup(PluginName));
                plugin = pluginResult.as<IVpnPlugIn>();
            }
            else
            {
                //
                // It looks like we don't have a plug-in instance yet, so we need to create a new plug-in instance and store it in
                // the property bag so that it can be retrieved by any future calls to this Run method
                //
                plugin = make<VpnPlugInImpl>();

                if (appProperties.Insert(PluginName, plugin) == TRUE)
                {
                    throw winrt::hresult_error(E_UNEXPECTED, L"Reinsertion of store App Name");
                }
            }

            VpnChannel::ProcessEventAsync(plugin, taskInstance.TriggerDetails());
        }
        catch (hresult_error const&)
        {
            //
            // We catch the exception and output it for debugging, but we do not re-throw. The important thing is to make sure that we
            // complete the deferral so that the process will not get stuck in a 'Running' state.
            //
        }

        if (deferralObj != nullptr)
        {
            deferralObj.Complete();
        }
    }
}