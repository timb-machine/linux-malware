# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
# Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

from conans import python_requires, CMake, tools, AutoToolsBuildEnvironment
import os
from datetime import datetime

from conan_util.CbConanFile import CbConanFile

class SHORT_NAME(CbConanFile):
    name     = "SHORT_NAME"
    version  = "PACKAGE_VERSION"
    settings = "os", "compiler", "build_type", "arch"
    generators = "cmake"
    requires = "LLVM_VERSION", "ELFUTILS_VERSION", "BCC_VERSION", "BOOST_VERSION"
    build_requires = "CPPUTEST_VERSION"
    default_options = "Boost:shared=False", \
                      "Boost:without_program_options=False", \
                      "Boost:without_thread=False", \
                      "Boost:without_system=False", \
                      "Boost:without_serialization=False", \
                      "Boost:without_filesystem=False", \
                      "Boost:without_chrono=False", \
                      "Boost:fPIC=True", \
                      "elfutils:shared=False", \
                      "llvm:shared=False", \
                      "bcc:shared=False"

    def configure_cmake(self, cmake, env_build):
        def _find_lib_path(paths, name):
            li = []
            if paths is None:
                return li
            for path in paths:
                if name in path:
                    li.append(path)
            return li

        def _append_if_dir(paths, subpath):
            li = []
            for path in paths:
                # should probably us path separator
                newpath = path + '/' +  subpath
                if os.path.isdir(newpath):
                    li.append(newpath)
                else:
                    li.append(path)
            return li

        cmake.parallel = True

        inc_path = self.deps_cpp_info["bcc"].include_paths[0] + '/bcc:'

        for dep_name in self.deps_cpp_info.deps:
            dep = self.deps_cpp_info[dep_name]
            if len(dep.include_paths) > 0:
                inc_path += ':'.join(dep.include_paths)

        cmake.definitions['BCC_LIBRARY_PATHS'] = ';'.join(self.deps_cpp_info.lib_paths)

        if os.getenv("CPATH"):
            os.environ["CPATH"] += ':'.join(env_build.include_paths) + inc_path
        else:
            os.environ["CPATH"] = ':'.join(env_build.include_paths) + inc_path

        # ':' should be the path serparator for most things
        if os.getenv("LIBRARY_PATH") :
            os.environ["LIBRARY_PATH"] += ':'.join(env_build.library_paths)
        else:
            os.environ["LIBRARY_PATH"] = ':'.join(env_build.library_paths)

        llvm_lib_li = _find_lib_path(env_build.library_paths, 'llvm')
        llvm_lib_li = _append_if_dir(llvm_lib_li, '/cmake/llvm')
        cmake.definitions['LLVM_DIR'] = ';'.join(llvm_lib_li)


    def build(self):
        cmake = CMake(self)
        env_build = AutoToolsBuildEnvironment(self)

        with tools.environment_append(env_build.vars):
            if os.getenv("FAST_BUILD") != "1":
                cmake.configure(source_dir=self.source_folder + os.path.sep + "src")
                with open("%s/env" % (self.build_folder), 'w') as fh:
                    for key in os.environ:
                        fh.write(key + "=" + os.environ[key] + "\n")

            cmake.build()

    def package(self):
        self.copy("*.h", dst="include/bpf_probe", src="include", keep_path=True)
        self.copy("*.a", dst="lib", keep_path=False)
        self.copy("check_probe", dst="bin", src="bin")

    def package_info(self):
        self.cpp_info.includedirs = ["include"]
        self.cpp_info.libdirs     = ['lib']
        self.cpp_info.libs        = ['bpf-probe']