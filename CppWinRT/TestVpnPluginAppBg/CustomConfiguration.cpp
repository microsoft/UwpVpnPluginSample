#include "pch.h"
#include "CustomConfiguration.h"


using namespace winrt::Windows::Data::Xml;
using namespace winrt::Windows::Data::Xml::Dom;

using namespace winrt::Windows::Foundation;
using namespace winrt::Windows::Foundation::Collections;

using namespace winrt::Windows::Networking;


void CustomConfiguration::ParseConfiguration(const WCHAR* configXml, bool IsRecon, VpnChannel const& channel)
{
	IsReconnect = IsRecon;
	
	XmlDocument doc{};

	doc.LoadXml(configXml);


	IXmlNode root = doc.SelectSingleNode(L"pluginschema");

	if (root != nullptr)
	{
		for (uint32_t i = 0; i < root.ChildNodes().Length(); i++)
		{
			IXmlNode rootChild = root.ChildNodes().Item(i);
			winrt::hstring rootChildName = Utils::GetLowerHString(rootChild.NodeName());
			
			//V2 Addition
			if (L"v2" == rootChildName)
			{
				this->IsV2 = true;

				for (uint32_t j = 0; j < rootChild.ChildNodes().Length(); j++)
				{
					IXmlNode v2Child = rootChild.ChildNodes().Item(j);
					winrt::hstring v2ChildName = Utils::GetLowerHString(v2Child.NodeName());

					//perapp
					if (L"perapp" == v2ChildName)
					{

						for (uint32_t k = 0; k < v2Child.ChildNodes().Length(); k++)
						{
							IXmlNode perAppChild = v2Child.ChildNodes().Item(k);
							winrt::hstring perAppChildName = Utils::GetLowerHString(perAppChild.NodeName());

							winrt::hstring appname;
							VpnIPProtocol vpnIPProtocol = VpnIPProtocol::None;
							winrt::hstring remoteAddressRanges;
							winrt::hstring remotePortRanges;
							winrt::hstring appClaims;
							VpnAppIdType appType = VpnAppIdType::PackageFamilyName;
							VpnTrafficFilter filter( VpnAppId ( appType, appname ) );

							for (uint32_t l = 0; l < perAppChild.ChildNodes().Length(); l++)
							{
								IXmlNode appIdChild = perAppChild.ChildNodes().Item(l);
								winrt::hstring appIdChildName = Utils::GetLowerHString(appIdChild.NodeName());

								if (L"name" == appIdChildName)
								{
									appname = appIdChild.InnerText();
								}
								else if (L"type" == appIdChildName)
								{
									winrt::hstring type = Utils::GetLowerHString(appIdChild.InnerText());

									if (L"filepath" == type)
									{
										appType = VpnAppIdType::FilePath;
									}
									else if (L"fullyqualifiedbinaryname" == type)
									{
										appType = VpnAppIdType::FullyQualifiedBinaryName;
									}
									else if (L"packagefamilyname" == type)
									{
										appType = VpnAppIdType::PackageFamilyName;
									}
								}
								else if (L"remoteaddressranges" == appIdChildName)
								{
									remoteAddressRanges = appIdChild.InnerText();
								}
								else if (L"remoteportranges" == appIdChildName)
								{
									remotePortRanges = appIdChild.InnerText();
								}
								else if (L"appclaims" == appIdChildName)
								{
									appClaims = appIdChild.InnerText();
								}
								else if (L"protocol" == appIdChildName)
								{
									winrt::hstring protocol = Utils::GetLowerHString(appIdChild.InnerText());

									if (L"tcp" == protocol)
									{
										vpnIPProtocol = VpnIPProtocol::Tcp;
									}
									else if (L"udp" == protocol)
									{
										vpnIPProtocol = VpnIPProtocol::Udp;
									}
								}
							}

							if (appname != L"")
							{
								filter.AppId().Type(appType);
								filter.AppId().Value(appname);
							}

							filter.Protocol(vpnIPProtocol);

							if (remoteAddressRanges != L"")
							{
								filter.RemoteAddressRanges().Append(remoteAddressRanges);
							}

							if (remotePortRanges != L"")
							{
								filter.RemotePortRanges().Append(remotePortRanges);
							}

							if (appClaims != L"")
							{
								filter.AppClaims().Append(appClaims);
							}
							trafficFilterAssignment.TrafficFilterList().Append(filter);
						}

					}
				}
			}
			else if (L"ipaddress" == rootChildName)
			{
				clientIpV4 = rootChild.InnerText();
			}
			else if (L"ipaddressv6" == rootChildName)
			{
				clientIpV6 = rootChild.InnerText();
			}
			else if (L"port" == rootChildName)
			{
				portServiceName = rootChild.InnerText();
			}
			else if (L"transport" == rootChildName)
			{
				winrt::hstring transport = rootChild.InnerText();

				if (L"dual" == transport)
				{
					transportType = VPN_PLUGIN_TRANSPORT_TYPE::VPN_PLUGIN_TRANSPORT_TYPE_DUAL;
				}
				else if (L"udp" == transport)
				{
					transportType = VPN_PLUGIN_TRANSPORT_TYPE::VPN_PLUGIN_TRANSPORT_TYPE_UDP;
				}
				else
				{
					transportType = VPN_PLUGIN_TRANSPORT_TYPE::VPN_PLUGIN_TRANSPORT_TYPE_TCP;
				}
			}
			else if (L"maxframesize" == rootChildName)
			{
				winrt::hstring strFrameSize = rootChild.InnerText();

				// Convert the frame size from String to UINT32
				std::wstring wFrameSize(strFrameSize.data());
				maxFrameSize = static_cast<unsigned int>(std::stoul(wFrameSize));
			}
			else if (L"ssl" == rootChildName)
			{
				for (uint32_t j = 0; j < rootChild.ChildNodes().Length(); j++)
				{
					IXmlNode sslChild = rootChild.ChildNodes().Item(j);
					winrt::hstring sslChildName = Utils::GetLowerHString(sslChild.NodeName());
					winrt::hstring sslInner = Utils::GetLowerHString(sslChild.InnerText());
					if (L"socketprotectionlevel" == sslChildName)
					{
						if (L"ssl" == sslInner)
						{
							protectionLevel = SocketProtectionLevel::Ssl;
						}
						else if (L"sslallownullencryption" == sslInner)
						{
							protectionLevel = SocketProtectionLevel::SslAllowNullEncryption;
						}
					}
				}
			}
			else if (L"customui" == rootChildName)
			{
				for (uint32_t j = 0; j < rootChild.ChildNodes().Length(); j++)
				{
					IXmlNode customuiChild = rootChild.ChildNodes().Item(j);
					winrt::hstring customuiChildName = Utils::GetLowerHString(customuiChild.NodeName());
					if (L"preauth" == customuiChildName)
					{
						for (uint32_t k = 0; k < customuiChild.ChildNodes().Length(); k++)
						{
							IXmlNode preauthChild = root.ChildNodes().Item(k);
							winrt::hstring preauthChildName = Utils::GetLowerHString(preauthChild.NodeName());

							if (L"prompt" == preauthChildName)
							{
								IVector<IVpnCustomPrompt> customPrompt{ winrt::single_threaded_vector<IVpnCustomPrompt>() };

								if (ConvertXmlToCustomPrompt(preauthChild, customPrompt))
								{
									preAuthCustomPrompts.push_back(customPrompt);
								}
							}
						}
					}
					else if (L"postauth" == customuiChildName)
					{
						for (uint32_t k = 0; k < customuiChild.ChildNodes().Length(); k++)
						{
							IXmlNode postauthChild = root.ChildNodes().Item(k);
							winrt::hstring postauthChildName = Utils::GetLowerHString(postauthChild.NodeName());
							
							if (L"prompt" == postauthChildName)
							{
								IVector<IVpnCustomPrompt> customPrompt{ winrt::single_threaded_vector<IVpnCustomPrompt>() };

								if (ConvertXmlToCustomPrompt(postauthChild, customPrompt))
								{
									postAuthCustomPrompts.push_back(customPrompt);
								}
							}
						}
					}
				}
			}
			else if (L"credentials" == rootChildName)
			{
				for (uint32_t j = 0; j < rootChild.ChildNodes().Length(); j++)
				{
					IXmlNode credentialsChild = rootChild.ChildNodes().Item(j);
					winrt::hstring credentialsChildName = Utils::GetLowerHString(credentialsChild.NodeName());

					if (L"credential" == credentialsChildName)
					{
						VPN_AUTHENTICATION auth;
						auth.useSingleSignOn = true;

						for (uint32_t k = 0; k < credentialsChild.ChildNodes().Length(); k++)
						{
							IXmlNode credChild = credentialsChild.ChildNodes().Item(k);
							winrt::hstring credChildName = Utils::GetLowerHString(credChild.NodeName());
							
							if (L"type" == credChildName)
							{
								winrt::hstring credChildInner = Utils::GetLowerHString(credChild.InnerText());
								if (L"otp" == credChildInner)
								{
									auth.authType = VpnCredentialType::UsernameOtpPin;
								}
								else if (L"userpasspin" == credChildInner)
								{
									auth.authType = VpnCredentialType::UsernamePasswordAndPin;
								}
								else if (L"passchange" == credChildInner)
								{
									auth.authType = VpnCredentialType::UsernamePasswordChange;
								}
								else if (L"smartcard" == credChildInner)
								{
									auth.authType = VpnCredentialType::SmartCard;
								}
								else if (L"protectedcert" == credChildInner)
								{
									auth.authType = VpnCredentialType::ProtectedCertificate;
								}
								else if (L"unprotectedcert" == credChildInner)
								{
									auth.authType = VpnCredentialType::UnProtectedCertificate;
								}
								else
								{
									auth.authType = VpnCredentialType::UsernamePassword;
								}
							}
							else if (L"user" == credChildName)
							{
								auth.expectedUser = credChild.InnerText();
							}
							else if (L"pass" == credChildName)
							{
								auth.expectedPass = credChild.InnerText();
							}
							else if (L"newpass" == credChildName)
							{
								auth.expectedNewPass = credChild.InnerText();
							}
							else if (L"pin" == credChildName)
							{
								auth.expectedPin = credChild.InnerText();
							}
							else if (L"certsubject" == credChildName)
							{
								auth.certSubject = credChild.InnerText();
							}
							else if (L"sso" == credChildName)
							{
								winrt::hstring credChildInner = Utils::GetLowerHString(credChild.InnerText());
								if (L"true" == credChildInner)
								{
									auth.useSingleSignOn = true;
								}
							}
							authentications.push_back(auth);
						}
					}
				}
			}
			else if(L"networkingsettings" == rootChildName)
			{
				for (uint32_t j = 0; j < rootChild.ChildNodes().Length(); j++)
				{
					IXmlNode settingChild = rootChild.ChildNodes().Item(j);
					winrt::hstring settingChildName = Utils::GetLowerHString(settingChild.NodeName());

					if (L"routes" == settingChildName)
					{
						for (uint32_t k = 0; k < settingChild.ChildNodes().Length(); k++)
						{
							IXmlNode routesChild = settingChild.ChildNodes().Item(k);
							winrt::hstring routesChildName = Utils::GetLowerHString(routesChild.NodeName());
							if (L"includev4" == routesChildName)
							{
								for (uint32_t l = 0; l < routesChild.ChildNodes().Length(); l++)
								{
									IXmlNode includev4Child = routesChild.ChildNodes().Item(l);
									winrt::hstring includev4ChildName = Utils::GetLowerHString(includev4Child.NodeName());
									if (L"route" == includev4ChildName)
									{
										VpnRoute route = nullptr;
										if (ConvertXmlToRoute(includev4Child, route))
										{
											ipv4InclusionRoutes.Append(route);
										}
									}
								}
							}
							else if (L"excludev4" == routesChildName)
							{
								for (uint32_t l = 0; l < routesChild.ChildNodes().Length(); l++)
								{
									IXmlNode excludev4Child = routesChild.ChildNodes().Item(l);
									winrt::hstring excludev4ChildName = Utils::GetLowerHString(excludev4Child.NodeName());
									if (L"route" == excludev4ChildName)
									{
										VpnRoute route = nullptr;
										if (ConvertXmlToRoute(excludev4Child, route))
										{
											ipv4ExclusionRoutes.Append(route);
										}
									}
								}
							}
							else if (L"includev6" == routesChildName)
							{
								for (uint32_t l = 0; l < routesChild.ChildNodes().Length(); l++)
								{
									IXmlNode includev6Child = routesChild.ChildNodes().Item(l);
									winrt::hstring includev6ChildName = Utils::GetLowerHString(includev6Child.NodeName());
									if (L"route" == includev6ChildName)
									{
										VpnRoute route = nullptr;
										if (ConvertXmlToRoute(includev6Child, route))
										{
											ipv6InclusionRoutes.Append(route);
										}
									}
								}
							}
							else if (L"excludev6" == routesChildName)
							{
								for (uint32_t l = 0; i < routesChild.ChildNodes().Length(); l++)
								{
									IXmlNode excludev6Child = routesChild.ChildNodes().Item(l);
									winrt::hstring excludev6ChildName = Utils::GetLowerHString(excludev6Child.NodeName());
									if (L"route" == excludev6ChildName)
									{
										VpnRoute route = nullptr;
										if (ConvertXmlToRoute(excludev6Child, route))
										{
											ipv6ExclusionRoutes.Append(route);
										}
									}
								}
							}
							else if (L"excludelocalsubnets" == routesChildName)
							{
								winrt::hstring routesInner = Utils::GetLowerHString(routesChild.InnerText());
								if (L"true" == routesInner)
								{
									excludeLocalSubnets = true;
								}
							}
						}
					}
				}
			}
			else if (L"namespaces" == rootChildName)
			{
				for (uint32_t j = 0; j < rootChild.ChildNodes().Length(); j++)
				{
					IXmlNode namespacesChild = rootChild.ChildNodes().Item(j);
					winrt::hstring namespacesChildName = Utils::GetLowerHString(namespacesChild.NodeName());

					if (L"proxyautoconfig" == namespacesChildName)
					{
						if (IsV2)
						{
							domainnameAssignment.ProxyAutoConfigurationUri(Uri(namespacesChild.InnerText()));
						}
						else
						{
							namespaceAssignment.ProxyAutoConfigUri(Uri(namespacesChild.InnerText()));
						}
					}
					else if (L"namespace" == namespacesChildName)
					{
						winrt::hstring space;
						IVector<HostName> dnsServerList{ winrt::single_threaded_vector<HostName>() };
						IVector<HostName> proxyServerList{ winrt::single_threaded_vector<HostName>() };

						for (uint32_t k = 0; k < namespacesChild.ChildNodes().Length(); k++)
						{
							IXmlNode namespaceChild = root.ChildNodes().Item(k);
							winrt::hstring namespaceChildName = Utils::GetLowerHString(namespaceChild.NodeName());

							if (L"space" == namespaceChildName)
							{
								space = namespaceChild.InnerText();
							}
							else if (L"dnsservers" == namespaceChildName)
							{
								for (uint32_t l = 0; l < namespaceChild.ChildNodes().Length(); l++)
								{
									IXmlNode dnsserversChild = namespaceChild.ChildNodes().Item(l);
									winrt::hstring dnsserversChildName = Utils::GetLowerHString(dnsserversChild.NodeName());

									if (L"server" == dnsserversChildName)
									{
										HostName dnsServer(dnsserversChild.InnerText());
										dnsServerList.Append(dnsServer);
									}
								}
							}
							else if (L"proxyservers" == namespaceChildName)
							{
								for (uint32_t l = 0; l < namespaceChild.ChildNodes().Length(); l++)
								{
									IXmlNode proxyserversChild = namespaceChild.ChildNodes().Item(l);
									winrt::hstring proxyserversChildName = Utils::GetLowerHString(proxyserversChild.NodeName());

									if (L"server" == proxyserversChildName)
									{
										HostName proxyServer(proxyserversChild.InnerText());
										dnsServerList.Append(proxyServer);
									}
								}
							}
						}

						// We are expected to pass nullptr instead of empty vectors
						if (proxyServerList.Size() == 0)
						{
							proxyServerList = nullptr;
						}

						if (dnsServerList.Size() == 0)
						{
							dnsServerList = nullptr;
						}

						if (space != L"")
						{
							if (IsV2)
							{
								VpnDomainNameInfo domainNameInfo(space, VpnDomainNameType::Suffix, dnsServerList, proxyServerList);
								domainnameList.push_back(domainNameInfo);
							}
							else
							{
								VpnNamespaceInfo namespaceInfo = VpnNamespaceInfo(space, dnsServerList, proxyServerList);
								namespaceList.Append(namespaceInfo);
							}
						}
					}
				}
			}
			else if (L"reconnect" == rootChildName)
			{
				for (uint32_t j = 0; j < rootChild.ChildNodes().Length(); j++)
				{
					IXmlNode reconnectChild = rootChild.ChildNodes().Item(j);
					winrt::hstring reconnectChildName = Utils::GetLowerHString(reconnectChild.NodeName());

					if (L"ipaddress" == reconnectChildName)
					{
						clientIpReconnectV4 = reconnectChild.InnerText();
					}
					else if (L"ipAddressv6" == reconnectChildName)
					{
						clientIpReconnectV6 = reconnectChild.InnerText();
					}
				}
			}
			else if (L"packetcapture" == rootChildName)
			{
				if (L"true" == Utils::GetLowerHString(rootChild.InnerText()))
				{
					packetCapture = true;
				}
			}
			else if (L"buffercapture" == rootChildName)
			{
				if (L"true" == Utils::GetLowerHString(rootChild.InnerText()))
				{
					bufferCapture = true;
				}
			}
		}
	}
	else
	{
		channel.LogDiagnosticMessage(L"Warning: CustomConfiguration XML schema appears to be invalid. Root element 'pluginschema' was not found.");
	}

	//
	// Check to see if we need to auto-generate a IP address for this client
	// Handle the case in which there is no custom configuration (or we received incomplete/invalid xml schema)
	//
	if (clientIpV4 == L"auto" || (clientIpV4 == L"" && clientIpV6 == L""))
	{
		//
		// If the ip address is specified as "auto" then it's an indication that the plug-in should try to randomize it's IP address to avoid collisions
		// with other VPN plug-in's connected to the same server/network. In this case, we still use the default 172.10.10. prefix, but we randomly generate
		// the last octet of the IP address (note that 172.10.10.1 through 172.10.10.15 are reserved for manual testing and will not be randomly picked here).
		// This is by no means perfect and collisions are still possible. A better long term solution will be to have a protocol with the VPN server and to
		// let the server assign the client's address dynamically.
		//
		clientIpV4 = L"172.10.10." + std::to_wstring(GenerateRandomInt(16, 254));
	}
	else if (clientIpV6 == L"auto")
	{
		clientIpV6 = L"fe7f::90:" + std::to_wstring(GenerateRandomInt(16, 254));
	}

	//
	// If this is a reconnect and we have been given some reconnection settings in the custom configuration
	// then we should apply them now
	//
	if (IsReconnect)
	{
		if (clientIpReconnectV4 != L"")
		{
			clientIpV4 = clientIpReconnectV4;
		}
		if (clientIpReconnectV6 != L"")
		{
			clientIpV6 = clientIpReconnectV6;
		}
	}

	//
	// Finish assigning any routes or namespaces that were specified via the custom configuration. If the lists
	// are of zero length then we pass nullptr instead of a zero length vector.
	//
	if (ipv4InclusionRoutes.Size() == 0 &&
		ipv4ExclusionRoutes.Size() == 0 &&
		ipv6InclusionRoutes.Size() == 0 &&
		ipv6ExclusionRoutes.Size() == 0)
	{
		routeAssignment = nullptr;
	}
	else
	{
		if (ipv4InclusionRoutes.Size() > 0)
		{
			routeAssignment.Ipv4InclusionRoutes(ipv4InclusionRoutes);
		}

		if (ipv4ExclusionRoutes.Size() > 0)
		{
			routeAssignment.Ipv4ExclusionRoutes(ipv4ExclusionRoutes);
		}

		if (ipv6InclusionRoutes.Size() > 0)
		{
			routeAssignment.Ipv6InclusionRoutes(ipv6InclusionRoutes);
		}

		if (ipv6ExclusionRoutes.Size() > 0)
		{
			routeAssignment.Ipv6ExclusionRoutes(ipv6ExclusionRoutes);
		}

		routeAssignment.ExcludeLocalSubnets(excludeLocalSubnets);

		if (IsV2)
		{
			if (domainnameList.size() > 0)
			{
				for each (VpnDomainNameInfo info in domainnameList)
				{
					domainnameAssignment.DomainNameList().Append(info);
				}
			}
			else
			{
				if (domainnameAssignment.ProxyAutoConfigurationUri() == nullptr)
				{
					domainnameAssignment = nullptr;
				}
			}
		}
		else
		{
			if (namespaceList.Size() > 0)
			{
				namespaceAssignment.NamespaceList(namespaceList);
			}
			else
			{
				if (namespaceAssignment.ProxyAutoConfigUri() == nullptr)
				{
					namespaceAssignment = nullptr;
				}
			}
		}

		if (portServiceName == L"")
		{
			//
			// We didn't receive a port via custom configuration, so instead we try to read the port directly from the channel configuration.
			// If that's not set (i.e. we receive port 0) then we use a default port for testing purposes
			//            
			if (channel.Configuration().ServerServiceName() == L"0")
			{
				portServiceName = defaultPort;
			}
			else
			{
				portServiceName = channel.Configuration().ServerServiceName();
			}
		}
	}
}




bool CustomConfiguration::ConvertXmlToCustomPrompt(IXmlNode promptXml, IVector<IVpnCustomPrompt>& customPrompt)
{
	for (uint32_t i = 0; i < promptXml.ChildNodes().Length(); i++)
	{
		IXmlNode promptXmlChild = promptXml.ChildNodes().Item(i);
		winrt::hstring promptXmlChildName = Utils::GetLowerHString(promptXmlChild.NodeName());

		if (L"editbox" == promptXmlChildName)
		{
			VpnCustomEditBox editBox;
			for (uint32_t j = 0; j < promptXmlChild.ChildNodes().Length(); j++)
			{
				IXmlNode editboxChild = promptXmlChild.ChildNodes().Item(j);
				winrt::hstring editboxChildName = Utils::GetLowerHString(editboxChild.NodeName());

				if (L"label" == editboxChildName)
				{
					editBox.Label(editboxChild.InnerText());
				}
				else if (L"defaulttext" == editboxChildName)
				{
					editBox.DefaultText(editboxChild.InnerText());
				}
				else if (L"compulsory" == editboxChildName)
				{
					if (L"true" == editboxChild.InnerText())
					{
						editBox.Compulsory(true);
					}
					else if (L"false" == editboxChild.InnerText())
					{
						editBox.Compulsory(false);
					}
				}
				else if (L"noecho" == editboxChildName)
				{
					if (L"true" == editboxChild.InnerText())
					{
						editBox.NoEcho(true);
					}
					else if (L"false" == editboxChild.InnerText())
					{
						editBox.NoEcho(false);
					}
				}
				else if (L"bordered" == editboxChild.InnerText())
				{
					if (L"true" == editboxChildName)
					{
						editBox.Bordered(true);
					}
					else if (L"false" == editboxChild.InnerText())
					{
						editBox.Bordered(false);
					}
				}
			}

			customPrompt.Append(editBox);
		}
		else if (L"combobox" == promptXmlChildName)
		{
			VpnCustomComboBox comboBox;
			for (uint32_t j = 0; j < promptXmlChild.ChildNodes().Length(); j++)
			{
				IXmlNode comboBoxChild = promptXmlChild.ChildNodes().Item(j);
				winrt::hstring comboBoxChildName = Utils::GetLowerHString(comboBoxChild.NodeName());

				if (L"label" == comboBoxChildName)
				{
					comboBox.Label(comboBoxChild.InnerText());
				} 
				else if (L"compulsory" == comboBoxChildName)
				{
					if (L"true" == comboBoxChild.InnerText())
					{
						comboBox.Compulsory(true);
					}
					else if (L"false" == comboBoxChild.InnerText())
					{
						comboBox.Compulsory(false);
					}
				}
				else if (L"bordered" == comboBoxChildName)
				{
					if (L"true" == comboBoxChild.InnerText())
					{
						comboBox.Bordered(true);
					}
					else if (L"false" == comboBoxChild.InnerText())
					{
						comboBox.Bordered(false);
					}
				}
				else if (L"options" == comboBoxChildName)
				{
					
					IVector<winrt::hstring> options{ winrt::single_threaded_vector<winrt::hstring>() };
					
					for (uint32_t k = 0; k < comboBoxChild.ChildNodes().Length(); k++)
					{
						IXmlNode optionNode = comboBoxChild.ChildNodes().Item(k);
						winrt::hstring optionNodeName = Utils::GetLowerHString(optionNode.NodeName());

						if (L"option" == optionNodeName)
						{
							options.Append(optionNode.InnerText());
						}
					}

					if (options.Size() > 0)
					{
						
						comboBox.OptionsText(options.GetView());
					}
				}
			}
			customPrompt.Append(comboBox);
		}
		else if (L"textbox" == promptXmlChildName)
		{
			VpnCustomTextBox textBox;
			for (uint32_t j = 0; j < promptXmlChild.ChildNodes().Length(); j++)
			{
				IXmlNode textboxChild = promptXmlChild.ChildNodes().Item(j);
				winrt::hstring textboxChildName = Utils::GetLowerHString(textboxChild.NodeName());

				if (L"label" == textboxChildName)
				{
					textBox.Label(textboxChild.InnerText());
				}
				else if (L"text" == textboxChildName)
				{
					textBox.DisplayText(textboxChild.InnerText());
				}
				else if (L"compulsory" == textboxChildName)
				{
					if (L"true" == textboxChild.InnerText())
					{
						textBox.Compulsory(true);
					}
					else if (L"false" == textboxChild.InnerText())
					{
						textBox.Compulsory(false);
					}
				}
				else if (L"bordered" == textboxChildName)
				{
					if (L"true" == textboxChild.InnerText())
					{
						textBox.Bordered(true);
					}
					else if (L"false" == textboxChild.InnerText())
					{
						textBox.Bordered(false);
					}
				}
			}

			customPrompt.Append(textBox);
		}
		else if (L"checkbox" == promptXmlChildName)
		{
		VpnCustomCheckBox checkBox;
		for (uint32_t j = 0; j < promptXmlChild.ChildNodes().Length(); j++)
		{
			IXmlNode checkBoxChild = promptXmlChild.ChildNodes().Item(j);
			winrt::hstring checkBoxChildName = Utils::GetLowerHString(checkBoxChild.NodeName());

			if (L"label" == checkBoxChildName)
			{
				checkBox.Label(checkBoxChild.InnerText());
			}
			else if (L"checked" == checkBoxChildName)
			{
				if (L"true" == checkBoxChild.InnerText())
				{
					checkBox.InitialCheckState(true);
				}
				else if (L"false" == checkBoxChild.InnerText())
				{
					checkBox.InitialCheckState(false);
				}
			}
			else if (L"compulsory" == checkBoxChildName)
			{
				if (L"true" == checkBoxChild.InnerText())
				{
					checkBox.Compulsory(true);
				}
				else if (L"false" == checkBoxChild.InnerText())
				{
					checkBox.Compulsory(false);
				}
			}
			else if (L"bordered" == checkBoxChildName)
			{
				if (L"true" == checkBoxChild.InnerText())
				{
					checkBox.Bordered(true);
				}
				else if (L"false" == checkBoxChild.InnerText())
				{
					checkBox.Bordered(false);
				}
			}
		}

		customPrompt.Append(checkBox);
		}
		else if (L"errorbox" == promptXmlChildName)
		{
		VpnCustomErrorBox errorBox;
		for (uint32_t j = 0; j < promptXmlChild.ChildNodes().Length(); j++)
		{
			IXmlNode errorBoxChild = promptXmlChild.ChildNodes().Item(j);
			winrt::hstring errorBoxChildName = Utils::GetLowerHString(errorBoxChild.NodeName());

			if (L"label" == errorBoxChildName)
			{
				errorBox.Label(errorBoxChild.InnerText());
			}
			else if (L"bordered" == errorBoxChildName)
			{
				if (L"true" == errorBoxChild.InnerText())
				{
					errorBox.Bordered(true);
				}
				else if (L"false" == errorBoxChild.InnerText())
				{
					errorBox.Bordered(false);
				}
			}
		}
		customPrompt.Append(errorBox);
		}
	}

	if (customPrompt.Size() > 0)
	{
		return true;
	}
	return false;
}

bool CustomConfiguration::ConvertXmlToRoute(IXmlNode routeXml, VpnRoute& route)
{
	HostName hostName = nullptr;
	uint8_t prefixSize = 0;

	for (uint32_t i = 0; i < routeXml.ChildNodes().Length(); i++)
	{
		IXmlNode routeChild = routeXml.ChildNodes().Item(i);
		winrt::hstring routeChildName = Utils::GetLowerHString(routeChild.NodeName());

		if (L"address" == routeChildName)
		{
			hostName = HostName(routeChild.InnerText());
		}
		else if (L"prefix" == routeChildName)
		{
			winrt::hstring prefix = routeChild.InnerText();
			std::wstring wPrefix(prefix.data());
			prefixSize = static_cast<unsigned char>(std::stol(wPrefix));
		}
	}
	
	if (L"" != hostName.DisplayName())
	{
		route = VpnRoute(hostName, prefixSize);
		return true;
	}
	return false;
}

int CustomConfiguration::GenerateRandomInt(int min, int max)
{
	int rnd;
	srand(static_cast<unsigned int>(time(0)));
	rnd = min + (rand() % (int)(max - min + 1));

	return rnd;
}
