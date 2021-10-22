using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;

// The Content Dialog item template is documented at https://go.microsoft.com/fwlink/?LinkId=234238

namespace TestVpnPluginApp
{
    public sealed partial class CredentialsDialog : ContentDialog
    {
        public ValueSet valueSet;
        public CredentialsDialog()
        {
            this.InitializeComponent();
            valueSet = new ValueSet();
        }


        private void Submit_PrimaryButtonClick(ContentDialog sender, ContentDialogButtonClickEventArgs args)
        {
            valueSet.Add("Username", Username.Text);
            valueSet.Add("Password", Password.Password);
        }
    }
}
