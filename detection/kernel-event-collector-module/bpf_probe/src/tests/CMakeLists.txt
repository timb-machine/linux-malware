# Copyright 2021 VMware Inc.  All rights reserved.
# SPDX-License-Identifier: GPL-2.0

if (NOT ${LOCAL_BUILD})
    cb_run_tests(NAME          RunAllTests
                 TARGETS       RunAllTests.cpp
                               BpfApi_tests.cpp
                 LIBRARIES     CONAN_PKG::CppUTest
                               bpf-probe
                 DEPENDENCIES  check_probe
                 UNIT)
endif()