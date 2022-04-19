// Copyright (c) 2021 VMWare, Inc. All rights reserved.
// SPDX-License-Identifier: GPL-2.0

#include "mock/BpfApi_Mock.h"
#include "BpfProgram.h"
#include "EventFactory.h"

#include "CppUTest/TestHarness.h"

using namespace cb_endpoint::bpf_probe;
using namespace cb_endpoint::bpf_probe::tdd_mock;

static const char *NAME_A = "NAME_A";
static const char *NAME_B = "NAME_B";
static const char *NAME_C = "NAME_C";
static const char *NAME_D = "NAME_D";

static const BpfProgram::ProbePoint test_hook_list[] = {
    BPF_ENTRY_HOOK (NAME_A, NAME_A),
    BPF_RETURN_HOOK(NAME_B, NAME_A),
    BPF_OPTIONAL_RETURN_HOOK(NAME_C, NAME_A),
    BPF_ALTERNATE_RETURN_HOOK(NAME_C, NAME_D, NAME_A),

    BPF_ENTRY_HOOK(nullptr,nullptr)
};

TEST_GROUP(BpfApi)
{
    BpfApi_Mock::UPtr bpfApi;

    void setup()
    {
        bpfApi = std::unique_ptr<BpfApi_Mock>(new BpfApi_Mock());
    }

    void teardown()
    {
        mock().checkExpectations();
        mock().clear();
        mock().removeAllComparatorsAndCopiers();
    }
};

TEST(BpfApi, InstallHooks_AttachFail)
{
    bpfApi->setup_AttachProbe(NAME_A, NAME_A, BpfApi::ProbeType::Entry, false);
    
    CHECK_FALSE(BpfProgram::InstallHooks(*bpfApi, test_hook_list));
}

TEST(BpfApi, InstallHooks_OptionalInstalled)
{
    bpfApi->setup_AttachProbe(NAME_A, NAME_A, BpfApi::ProbeType::Entry, true);
    bpfApi->setup_AttachProbe(NAME_B, NAME_A, BpfApi::ProbeType::Return, true);
    bpfApi->setup_AttachProbe(NAME_C, NAME_A, BpfApi::ProbeType::Return, true);

    CHECK_TRUE(BpfProgram::InstallHooks(*bpfApi, test_hook_list));
}

TEST(BpfApi, InstallHooks_OptionalSkipped)
{
    bpfApi->setup_AttachProbe(NAME_A, NAME_A, BpfApi::ProbeType::Entry, true);
    bpfApi->setup_AttachProbe(NAME_B, NAME_A, BpfApi::ProbeType::Return, true);
    bpfApi->setup_AttachProbe(NAME_C, NAME_A, BpfApi::ProbeType::Return, false);
    bpfApi->setup_AttachProbe(NAME_D, NAME_A, BpfApi::ProbeType::Return, true);

    CHECK_TRUE(BpfProgram::InstallHooks(*bpfApi, test_hook_list));
}

TEST(BpfApi, MockInit)
{
    CHECK(bpfApi);
}

TEST(BpfApi, EventFactory)
{
    CHECK(EventFactory::Fork(0, 0, 0));
}
