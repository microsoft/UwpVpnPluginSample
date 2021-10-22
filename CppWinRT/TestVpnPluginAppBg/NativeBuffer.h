/*++

Copyright (c) 2019 Microsoft Corporation

Module Name:

    NativeBuffer.h

Abstract:

     Native buffer that's implements IBuffer and does not perform an alloc.

--*/

#include "pch.h"

using namespace winrt::Windows::Storage::Streams;

namespace winrt::TestVpnPluginAppBg::implementation
{
    struct __declspec(uuid("905a0fef-bc53-11df-8c49-001e4fc686da")) IBufferByteAccess : ::IUnknown
    {
        virtual HRESULT __stdcall Buffer(void** value) = 0;
    };

    struct NativeBuffer : implements<NativeBuffer, IBuffer, IBufferByteAccess>
    {
        unsigned char* m_pointer;
        uint32_t m_length{};
        uint32_t m_capacity{};

        NativeBuffer(unsigned char* pointer, uint32_t capacity) :
            m_pointer(pointer), m_capacity(capacity)
        {
        }

        uint32_t Capacity() const
        {
            return m_capacity;
        }

        uint32_t Length() const
        {
            return m_length;
        }

        void Length(uint32_t value)
        {
            if (value > m_capacity)
            {
                throw hresult_invalid_argument();
            }

            m_length = value;
        }

        HRESULT __stdcall Buffer(void** value) final
        {
            *value = m_pointer;
            return S_OK;
        }
    };
}
