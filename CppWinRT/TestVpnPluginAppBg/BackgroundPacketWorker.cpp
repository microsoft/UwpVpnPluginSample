#include "pch.h"
#include "BackgroundPacketWorker.h"

using namespace winrt::impl;
using namespace Microsoft::WRL;
using namespace winrt::Windows::Foundation;

using namespace winrt::Windows::Storage::Streams;
using namespace winrt::Windows::Networking::Sockets;
using namespace winrt::Windows::ApplicationModel;

void BackgroundPacketWorker::AddPacket(VpnPacketBuffer buff)
{
	std::shared_lock<std::shared_mutex> lk(m);
	q.push(std::ref(buff));
	lk.unlock();
}

static void DecapPacketLambda(std::shared_mutex& m, std::queue<VpnPacketBuffer>& q, winrt::Windows::Networking::Vpn::VpnChannel const& channel, bool& isWorking, VPN_PLUGIN_DECAP_STATE& gDecapState) {
	std::shared_lock<std::shared_mutex> lk(m);
	while (!q.empty())
	{
		VpnPacketBuffer buf = q.front();
		q.pop();
		lk.unlock();

		uint32_t length = buf.Buffer().Length();
		uint8_t* data = buf.Buffer().data();
		
		if (gDecapState.currentSize == 1)
		{
			channel.LogDiagnosticMessage(L"Continuing a partial packet (need to determine packet version).");
			// Just need to copy 1 byte to determine packet version
			memcpy(gDecapState.currentPartialPacket + (sizeof(uint8_t)*gDecapState.currentSize), data, 1);
			gDecapState.currentSize = 2;

			//Shift data buffer
			uint8_t* shift = new uint8_t[length - 1]();
			memcpy(shift, data + (sizeof(uint8_t) * 1), length - 1);
			memcpy(data, shift, length - 1);
			length -= 1;

			ProcessPacketVersion(gDecapState.currentPartialPacket, 2, gDecapState);
		}

		//
		// If we've already consumed the whole frame buffer, then we are done. We still haven't finish decapsulating
		// the curent packet, but it will be stored in gDecapState and we will continue decap'ing when this
		// method is invoked again with more data.
		//
		if (length == 0)
		{
			goto LoopEnd;
		}

		//Attempt to figure out length of packet
		if (gDecapState.currentSize != 0 &&
			((!gDecapState.isV6 && (gDecapState.currentSize < VALID_LENGTH)) ||
			(gDecapState.isV6 && (gDecapState.currentSize < VALID_LENGTH_V6))))
		{
			channel.LogDiagnosticMessage(L"Continuing a partial packet (need to complete the ip header).");

			//
			// If we are here, then we ARE continuing with a partial packet, but it looks like we don't yet
			// have enough of the IPv4 header to even know the full length of the packet. So the first thing
			// we will do is copy over enough data from the frame byte array so that we can at least find out
			// the total length of the packet.
			//
			uint32_t validLength = (gDecapState.isV6) ? VALID_LENGTH_V6 : VALID_LENGTH;
			uint32_t lengthToCopy = min(validLength, length);
			memcpy(gDecapState.currentPartialPacket + (sizeof(uint8_t) * gDecapState.currentSize), data, lengthToCopy);
			gDecapState.currentSize += lengthToCopy;

			// Do we now have enough IPv4 header data to determine the full packet length?
			if (!gDecapState.isV6 && (gDecapState.currentSize >= VALID_LENGTH))
			{
				//
				// Yes, we have enough data, so get the total length of the packet in host order and store
				// it in the packetHostOrderTotalLength member for later use
				//
				FULL_CONTROL_HEADER_V4* v4Header = reinterpret_cast<FULL_CONTROL_HEADER_V4*>(gDecapState.currentPartialPacket);
				gDecapState.packetHostOrderTotalLength = ntohs(v4Header->fullHeader.ipv4Header.TotalLength);
			}

			// Do we now have enough IPv6 header data to determine the full packet length?
			if (gDecapState.isV6 && (gDecapState.currentSize >= VALID_LENGTH_V6))
			{
				//
				// Yes, we have enough data, so get the total length of the packet in host order and store
				// it in the packetHostOrderTotalLength member for later use
				//
				FULL_CONTROL_HEADER_V6* v6Header = reinterpret_cast<FULL_CONTROL_HEADER_V6*>(gDecapState.currentPartialPacket);
				gDecapState.packetHostOrderTotalLength = ntohs(v6Header->fullHeader.ipv6Header.PayloadLength) + IPV6_HEADER_LENGTH;
			}

			//Shift data buffer
			length -= lengthToCopy;
			uint8_t* shift = new uint8_t[length]();
			memcpy(shift, data + (sizeof(uint8_t) * lengthToCopy), length);
			memcpy(data, shift, length);
		}

		//
		// If we've already consumed the whole frame buffer, then we are done. We still haven't finish decapsulating
		// the curent packet, but it will be stored in m_DecapState and we will continue decap'ing when this
		// method is invoked again with more data.
		//
		if (length == 0)
		{
			goto LoopEnd;
		}

		if (gDecapState.currentSize != 0)
		{
			channel.LogDiagnosticMessage(L"Full length of the partial packet is known (" + std::to_wstring(gDecapState.packetHostOrderTotalLength) + L"). See if we have enough data to satisfy the packet ");
		}

		//
		// If we are still working on a partial packet, then we should at least know the full length of the packet
		// now, so we need to check and see if we actually have enough remaining data in the frame to satify
		// the full packet.
		//
		if (gDecapState.currentSize != 0 &&
			((!gDecapState.isV6 && (gDecapState.currentSize >= VALID_LENGTH)) ||
				(gDecapState.isV6 && (gDecapState.currentSize >= VALID_LENGTH_V6))) &&
			(gDecapState.packetHostOrderTotalLength + 1 - gDecapState.currentSize) > length) //plus 1 for control packet
		{
			channel.LogDiagnosticMessage(L"We do NOT have enough data to satisfy the packet.");
			
			//
			// It looks like we don't have enough data to satisfy the full pending packet, so just copy all of the
			// data that we have in the frame byte array to m_DecapState and then return. We will continue decap'ing
			// the partial packet when we get invoked next time with more data.
			//
			memcpy(gDecapState.currentPartialPacket + (sizeof(uint8_t) * gDecapState.currentSize), data, length);
			gDecapState.currentSize += length;
			goto LoopEnd;
		}

		//
		// If we are still working on a partial packet, then we must now have enough data to satisfy the full
		// packet.
		//
		if (gDecapState.currentSize != 0 &&
			((!gDecapState.isV6 && (gDecapState.currentSize >= VALID_LENGTH)) ||
			(gDecapState.isV6 && (gDecapState.currentSize >= VALID_LENGTH_V6))) &&
			(gDecapState.packetHostOrderTotalLength + 1 - gDecapState.currentSize) <= length) //+ 1 for control packet
		{
			channel.LogDiagnosticMessage(L"We have enough data to satisfy the packet.");

			uint8_t* completePacket = new uint8_t[gDecapState.packetHostOrderTotalLength + 1]();

			// Copy what we had saved of the partial packet from gDecapState
			memcpy(completePacket, gDecapState.currentPartialPacket, gDecapState.currentSize);

			// Then copy the remainder of the packet from the frame buffer
			memcpy(completePacket + gDecapState.currentSize*(sizeof(uint8_t)), data, gDecapState.packetHostOrderTotalLength + 1 - gDecapState.currentSize);

			//FinishWithCurrentPacket
			
			
			//Shift data buffer
			length -= gDecapState.packetHostOrderTotalLength + 1 - gDecapState.currentSize;
			uint8_t* shift = new uint8_t[length]();
			memcpy(shift, data + (sizeof(uint8_t) * gDecapState.packetHostOrderTotalLength + 1 - gDecapState.currentSize), length);
			memcpy(data, shift, length);
		}

		//reset decapState since we finished the partial packet (or we never had one)
		gDecapState.currentPartialPacket = new uint8_t[PARTIAL_PACKET_SIZE]();
		gDecapState.currentSize = 0;
		gDecapState.isV6 = false;
		gDecapState.packetHostOrderTotalLength = 0;

		//
		// If we've already consumed the whole frame buffer, then we are done
		//
		if (length == 0)
		{
			goto LoopEnd;
		}

		channel.LogDiagnosticMessage(L"Starting to process the next packet.");

		//
		// If we reach this point, we must be starting to process a new packet
		//
		// Look at the frame bytes to see if we have enough of the next IPv4/IPv6 header to understand
		// the full length of the next packet. Again, VALID_LENGTH represents the amount of data we must
		// have in order to be able to read the TotalLength/PayloadLength field of the IPv4/IPv6 header
		//

		//We use this temporary currentState for the current packets, if we end up having a split packet we use gDecapState later
		VPN_PLUGIN_DECAP_STATE gCurrentState;
		gCurrentState.currentPartialPacket = new uint8_t[PARTIAL_PACKET_SIZE]();
		
		VPN_CONTROL control = GetAndHandleControlByte(data);

		while (control != VPN_CONTROL::VPN_CONTROL_PACKET)
		{
			if (control == VPN_CONTROL::VPN_CONTROL_DISCONNECT)
			{
				return;
			}

			//It was some other control message, so now we continue

			//Shift data buffer
			length -= 1;
			uint8_t* shift = new uint8_t[length]();
			memcpy(shift, data + sizeof(uint8_t), length);
			memcpy(data, shift, length);

			if (length == 0)
			{
				goto LoopEnd;
			}
			
			control = GetAndHandleControlByte(data);
		}

		if (length == 1)
		{
			goto PartialPacket;
		}

		ProcessPacketVersion(data, length, gCurrentState);

		//
		// We now enter a loop in which we will continue to process all of the fully-transmitted packets
		// within the frame buffer. The loop will exit when we finish processing all of the packets or 
		// reach a point at which we do not have enough data to fully satisfy the next packet.
		//
		channel.LogDiagnosticMessage(L"About to enter packet processing loop.");

		while (((gCurrentState.isV6 && (length > VALID_LENGTH_V6)) ||
			(!gCurrentState.isV6 && (length > VALID_LENGTH))) &&
			gCurrentState.packetHostOrderTotalLength + 1 <= length)
		{
			memcpy(gCurrentState.currentPartialPacket, data, gCurrentState.packetHostOrderTotalLength + 1);
			FinishWithCurrentPacket(channel, gCurrentState, gCurrentState.currentPartialPacket);

			//Shift data buffer
			length -= gCurrentState.packetHostOrderTotalLength + 1;
			uint8_t* shift = new uint8_t[length]();
			memcpy(shift, data + sizeof(uint8_t), length);
			memcpy(data, shift, length);

			// If buffer length is already down to 0, it means that we finished processing the whole buffer and we can exit the loop
			if (length == 0)
			{
				goto LoopEnd;
			}

			control = GetAndHandleControlByte(data);
			while (control != VPN_CONTROL::VPN_CONTROL_PACKET)
			{
				if (control == VPN_CONTROL::VPN_CONTROL_DISCONNECT)
				{
					return;
				}

				//It was some other control message, so now we continue

				//Shift data buffer
				length -= 1;
				uint8_t* shift = new uint8_t[length]();
				memcpy(shift, data + sizeof(uint8_t), length);
				memcpy(data, shift, length);

				if (length == 0)
				{
					goto LoopEnd;
				}

				control = GetAndHandleControlByte(data);
			}

			if (length == 1)
			{
				goto PartialPacket;
			}

			ProcessPacketVersion(data, length, gCurrentState);
			channel.LogDiagnosticMessage(L"Looping...");
		}
		channel.LogDiagnosticMessage(L"Exiting packet processing loop...");

	PartialPacket:
		//
		// If length == 0, we're done, otherwise
		// it looks like we do have a partial packet which intersected the frame, so we store the partial
		// packet in m_DecapState. We will continue decap'ing the partial packet when we get invoked next
		// time with more data.
		//
		if (length != 0)
		{
			channel.LogDiagnosticMessage(L"We have a partial packet to store. Length remaining i: " + winrt::to_hstring(length));

			memcpy(gDecapState.currentPartialPacket, data, length);
			gDecapState.currentSize = length;

			if (length == 1)
			{
				goto LoopEnd;
			}

			channel.LogDiagnosticMessage(L"Determining Packet type for partial packet.");
			ProcessPacketVersion(data, length, gDecapState);
		}

	LoopEnd:
		lk.lock();
	}
	lk.unlock();

	isWorking = false;
}

void BackgroundPacketWorker::EncapPacketLambda(winrt::Windows::Networking::Vpn::VpnChannel const& channel)
{
	std::shared_lock<std::shared_mutex> lk(m);
	while (!q.empty())
	{
		VpnPacketBuffer buf = q.front();
		q.pop();
		lk.unlock();

		uint32_t length = buf.Buffer().Length();
		uint8_t* data = buf.Buffer().data();
		
		uint8_t* shift = new uint8_t[length]();
		memcpy(shift, data, length);

		uint8_t controlByte[1] = { static_cast<uint8_t>(VPN_CONTROL::VPN_CONTROL_PACKET) };
		memcpy(data, controlByte, 1);
		
		
		buf.Buffer().Length(length + 1);
		memcpy(data + sizeof(uint8_t),shift, length);

		channel.AppendVpnSendPacketBuffer(buf);
		channel.FlushVpnSendPacketBuffers();

		lk.lock();
	}
	lk.unlock();

	isWorking = false;
}


void BackgroundPacketWorker::TryStartConsumePacketsThread(bool encap, winrt::Windows::Networking::Vpn::VpnChannel const& channel)
{
	if (isWorking)
	{
		return;
	}
	isWorking = true;

	if (encap)
	{
		//EncapPacketLambda(std::ref(m), std::ref(q), std::ref(channel), std::ref(isWorking));
		auto thread1 = std::thread(&BackgroundPacketWorker::EncapPacketLambda, this, std::cref(channel)); 
		thread1.join();
	}
	else 
	{
		DecapPacketLambda(std::ref(m), std::ref(q), std::ref(channel), std::ref(isWorking), std::ref(gDecapState));
	}
	
	/*auto thread1 = std::thread(ConsumePacketLambda, std::ref(m), std::ref(q), std::ref(channel), std::ref(isWorking));
	thread1.detach();*/
}

void FinishWithCurrentPacket(winrt::Windows::Networking::Vpn::VpnChannel const& channel, VPN_PLUGIN_DECAP_STATE& state, uint8_t* buffer)
{
	VpnPacketBuffer outPacket = nullptr;
	channel.RequestVpnPacketBuffer(VpnDataPathType::Receive, outPacket);

	memcpy(outPacket.Buffer().data(), buffer + sizeof(uint8_t), state.packetHostOrderTotalLength); //skip control bytes
	outPacket.Buffer().Length(state.packetHostOrderTotalLength);

	channel.AppendVpnReceivePacketBuffer(outPacket);
	channel.FlushVpnReceivePacketBuffers();

	channel.LogDiagnosticMessage(L"We are done with the current packet (length: " + std::to_wstring(state.packetHostOrderTotalLength) + L").");
}

void ProcessPacketVersion(uint8_t* buffer, uint32_t length, VPN_PLUGIN_DECAP_STATE& state)
{
	if (IsV6Packet(buffer))
	{
		if (length >= VALID_LENGTH_V6)
		{
			FULL_CONTROL_HEADER_V6* v6Header = reinterpret_cast<FULL_CONTROL_HEADER_V6*>(buffer);
			state.packetHostOrderTotalLength = ntohs(v6Header->fullHeader.ipv6Header.PayloadLength) + IPV6_HEADER_LENGTH;
		}
		state.isV6 = true;
	}
	else
	{
		if (length >= VALID_LENGTH)
		{
			FULL_CONTROL_HEADER_V4* v4Header = reinterpret_cast<FULL_CONTROL_HEADER_V4*>(buffer);
			state.packetHostOrderTotalLength = ntohs(v4Header->fullHeader.ipv4Header.TotalLength);
		}
		state.isV6 = false;
	}
}

bool IsV6Packet(uint8_t* buffer)
{
	uint8_t buffer1[40];
	BYTE buffer2[40];

	for (int i = 0; i < 40; i++)
	{
		buffer1[i] = *(buffer + sizeof(uint8_t) * i);
		buffer2[i] = *(buffer + sizeof(uint8_t) * i);
	}

	FULL_CONTROL_HEADER_V4* v4Header = reinterpret_cast<FULL_CONTROL_HEADER_V4*>(buffer);

	UINT8 version = v4Header->fullHeader.ipv4Header.VersionAndHeaderLength >> 4;

	if ((version != 4) && (version != 6))
	{
		throw winrt::hresult_error(ERROR, L"ERROR: Received a non-ipv4/ipv6 packet, packet version unknown.");
	}
	return (version == 6);
}



VPN_CONTROL GetAndHandleControlByte(uint8_t* buffer)
{
	FULL_CONTROL_HEADER_V4* fullheader = reinterpret_cast<FULL_CONTROL_HEADER_V4*>(buffer);


	VPN_CONTROL code = static_cast<VPN_CONTROL>(fullheader->ControlByte);

	switch (code)
	{
		case VPN_CONTROL::VPN_CONTROL_PACKET:
			break;
		case VPN_CONTROL::VPN_CONTROL_DISCONNECT:
		{
			//Unfortunately we can't just call the disconnect method, otherwise the server will instantly reconnect. We need to instead disconnect the profile
			VpnManagementAgent agent;

			auto vpnProfiles = agent.GetProfilesAsync().get();
			for (auto const& vpnProfile : vpnProfiles)
			{
				auto pluginProfile = vpnProfile.try_as<VpnPlugInProfile>();
				if ((pluginProfile != nullptr) &&
					(pluginProfile.ConnectionStatus() == VpnManagementConnectionStatus::Connected) &&
					(pluginProfile.VpnPluginPackageFamilyName() == Package::Current().Id().FamilyName()))
				{
					agent.DisconnectProfileAsync(pluginProfile).get();
					break;
				}
			}
			break;
		}
		case VPN_CONTROL::VPN_CONTROL_KEEP_ALIVE:
			break;
		default:
			throw winrt::hresult_error(ERROR, L"ERROR: Received an unknown control packet value.");
	}

	return code;
}
