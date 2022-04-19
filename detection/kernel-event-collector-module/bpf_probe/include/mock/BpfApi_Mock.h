/* Copyright (c) 2020 VMWare, Inc. All rights reserved. */
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#pragma once

#include "../BpfApi.h"

#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"

#ifndef __MOCKED_FUNCTION__
#define SETUP_PREFIX_LEN 6
#define __MOCKED_FUNCTION__ (__FUNCTION__ + SETUP_PREFIX_LEN)
#endif

namespace ebpf {
    class BPF {};
}

namespace cb_endpoint {
namespace bpf_probe {
namespace tdd_mock {

    class BpfApi_Mock
        : public IBpfApi
    {
    public:
        using UPtr = std::unique_ptr<BpfApi_Mock>;

        #define BPF_API_SCOPE "BpfApi"

        void setup_Init(bool result)
        {
            ::mock(BPF_API_SCOPE)
                    .expectOneCall(__MOCKED_FUNCTION__)
                    .andReturnValue((bool) result);
        }

        void setup_Reset(bool result)
        {
            ::mock(BPF_API_SCOPE)
                .expectOneCall(__MOCKED_FUNCTION__)
                .andReturnValue((bool) result);
        }

        void setup_AttachProbe(const char *name,
                                      const char *callback,
                                      BpfApi::ProbeType type,
                                      bool result)
        {
            ::mock(BPF_API_SCOPE)
                    .expectOneCall(__MOCKED_FUNCTION__)
                    .andReturnValue(result);
        }

        void setup_RegisterEventCallback(BpfApi::EventCallbackFn callback, bool result)
        {
            ::mock(BPF_API_SCOPE)
                    .expectOneCall(__MOCKED_FUNCTION__)
                    .andReturnValue(result);
        }

        void setup_PollEvents(int result)
        {
            ::mock(BPF_API_SCOPE)
                    .expectOneCall(__MOCKED_FUNCTION__)
                    .andReturnValue(result);
        }

        bool Init(const std::string & bpf_prog) override
        {
            ::mock(BPF_API_SCOPE)
                .actualCall(__FUNCTION__);
            return ::mock(BPF_API_SCOPE).boolReturnValue();
        }

        void Reset() override
        {
        }

        bool AttachProbe(const char * name,
                                      const char * callback,
                                      ProbeType    type) override
        {
            ::mock(BPF_API_SCOPE)
                .actualCall(__FUNCTION__);
            return ::mock(BPF_API_SCOPE).boolReturnValue();
        }

        bool RegisterEventCallback(EventCallbackFn callback) override
        {
            ::mock(BPF_API_SCOPE)
                .actualCall(__FUNCTION__);
            return ::mock(BPF_API_SCOPE).boolReturnValue();
        }

        int PollEvents() override
        {
            ::mock(BPF_API_SCOPE)
                .actualCall(__FUNCTION__);
            return ::mock(BPF_API_SCOPE).intReturnValue();
        }
    };
}
}
}


