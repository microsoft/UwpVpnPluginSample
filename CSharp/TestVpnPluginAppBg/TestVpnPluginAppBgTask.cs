//
// The following code implements the background tasks of the application. Currently, there are two background tasks:
// 
// #1 "VpnBackgroundTask"
//
//    You can think of this task as the entry point for your VPN plug-in. When your application is installed
//    this background task will automatically be registered by the VPN platform. The platform will then invoke this
//    background task whenever your VPN client needs to perform work (e.g. you need to connect or encapsulate packets).
//

using System;
using System.Collections.Generic;
using System.Diagnostics;
using Windows.ApplicationModel.Background;
using Windows.ApplicationModel.Core;
using Windows.Networking.Vpn;

namespace TestVpnPluginAppBg
{
    public sealed class VpnBackgroundTask : IBackgroundTask
    {
        /// <summary>
        /// String used to identify a stored TestVpnPlugin object within the application property bag
        /// </summary>
        private const string pluginId = "TestVpnPlugin";

        /// <summary>
        /// VPN background task - invoked by the platform whenever our client plugin needs to do some work. Within this background
        /// task it is expected that you will create/retrieve an instance of your IVpnPlugin (i.e. your implemented VPN plug-in) and pass
        /// the plug-in object to the VPN platform by calling ProcessEventAsync. At that point, the platform will begin to invoke the
        /// relevant methods of your plug-in object to do work (e.g. Connect, Encapsulate, etc).
        ///
        /// It is important that on each invocation of this background task, we provide the same instance of the IVpnPlugin object to the
        /// platform. This is because the plug-in will have internal state which needs to be preserved across multiple invocations (e.g. 
        /// the plug-in may have a partially decapsulated packet stored while it awaits more data to be available for decapsulation). In
        /// order to ensure that we use the same IVpnPlugin instance on each invocation of this task, we save the plugin object into the
        /// applications property bag the first time it is created. Any subsequent invocations of this task will first check the property
        /// bag to see if a plugin object already exists, and if so will retrieve it and pass that same instance to the platform each
        /// time.
        /// </summary>
        /// <param name="taskInstance">An interface to an instance of the background task</param>
        public void Run(IBackgroundTaskInstance taskInstance)
        {
            Debug.WriteLine("Entering VpnBackgroundTask Run.");

            // To keep the host process from being suspended or terminated while the background task is running

            BackgroundTaskDeferral _deferral = taskInstance.GetDeferral();
                
            try
            {
                // Our IVpnPlugin object which we will be passing to the platform so that it can be used to perform work

                TestVpnPlugin plugin;

                // First we need to look in the property bag to see if we already have an instantiated plug-in object from a previous invocation
                // of this task. It is important to ensure that we use the same instance of our plug-in each time this background task is
                // invoked, as the plug-in may have some internal state that needs to be maintained (e.g. partially decapsulated packets)

                if (((IDictionary<string, object>)CoreApplication.Properties).ContainsKey(pluginId))
                {
                    // We already have a plug-in instance (instantiated during a previous call to this Run method) so we can retrieve it

                    Debug.WriteLine("Retrieving existing plug-in instance.");
                    plugin = ((IDictionary<string, object>)CoreApplication.Properties)[pluginId] as TestVpnPlugin;
                }
                else
                {
                    // It looks like we don't have a plug-in instance yet, so we need to create a new plug-in instance and store it in
                    // the property bag so that it can be retrieved by any future calls to this Run method

                    Debug.WriteLine("Creating new plug-in instance.");

                    plugin = new TestVpnPlugin();
                    ((IDictionary<string, object>)CoreApplication.Properties).Add(pluginId, plugin);
                }

                // Now that we have our plug-in instance, we need to pass it to the VPN platform so that the platform can use it to perform
                // work (e.g. connect, encapsulate, etc). This call is blocking and the background task will not complete until the platform
                // has finished using our plug-in to do work (this call will return at that point).

                Debug.WriteLine("Calling ProcessEventAsync");
                VpnChannel.ProcessEventAsync(plugin, taskInstance.TriggerDetails);

                // We are done for now. Complete the deferral and exit the background task
            }
            catch (Exception ex)
            {
                // We catch the exception and output it for debugging, but we do not rethrow. The important thing is to make sure that we
                // complete the deferral so that the process will not get stuck in a 'Running' state.

                Debug.WriteLine(
                    String.Format("Exception during VpnBackgroundTask.Run: {0}.", ex.ToString())
                    );
            }
            finally
            {
                // We are done for now. Complete the deferral and exit the background task.

                _deferral.Complete();
            }

            Debug.WriteLine("Leaving VpnBackgroundTask Run.");
        }
    }
}
