#!/bin/bash
# Copyright 2021 VMware Inc.  All rights reserved.
# SPDX-License-Identifier: GPL-2.0

SOURCE_PROG=$1
OUT_FILE=$2

if [[ x"${SOURCE_PROG}" == x ]]
then
	exit 1
fi

if [[ ! -f "${SOURCE_PROG}" ]]
then
	echo "No source program: ${SOURCE_PROG}" 1>&2
	exit 1
fi

bcc_prog=$(cat ${SOURCE_PROG})
printf '#include "BpfProgram.h"\n' "${bcc_prog}" > "${OUT_FILE}"
printf 'const std::string cb_endpoint::bpf_probe::BpfProgram::DEFAULT_PROGRAM = R"(\n%s\n)";\n' "${bcc_prog}" >> "${OUT_FILE}"

