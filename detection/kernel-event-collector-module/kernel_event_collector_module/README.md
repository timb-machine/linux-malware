# Carbon Black Kernel Event Collector Module

## Overview
This repo contains the source for the Carbon Black Cloud kernel module.
The module is responsible for collecting a variety of events related to
processes, files, network connections, etc. All releases of the Carbon
Black Cloud Linux agent since version 2.9.0 are built with this
open-source kernel module (2.8 and earlier are built with a proprietary
version of the module).

## Try it out
Installing the kernel module will expose some of the collected information in
the `/proc/event_collector` directory.
```shell script
sudo insmod event_collector_1_0_0
sudo cat /proc/event_collector/proc-track-table
```


### Supported Kernel Versions
This module is primarily designed to support Redhat 6/7/8 kernels. The
officially supported kernel modules are listed below.

###### Redhat 6
* `2.6.32-504` (6.6)
* `2.6.32-573` (6.7)
* `2.6.32-642` (6.8)
* `2.6.32-696` (6.9)
* `2.6.32-754` (6.10)

###### Redhat 7
* `3.10.0-123` (7.0)
* `3.10.0-229` (7.1)
* `3.10.0-327` (7.2)
* `3.10.0-514` (7.3)
* `3.10.0-693` (7.4)
* `3.10.0-862` (7.5)
* `3.10.0-957` (7.6)
* `3.10.0-1062` (7.7)
* `3.10.0-1127` (7.8)
* `3.10.0-1160` (7.9)

###### Redhat 8
* `4.18.0-80` (8.0)
* `4.18.0-147` (8.1)
* `4.18.0-193` (8.2)
* `4.18.0-240` (8.3)

### Prerequisites
GCC, CMake, and the kernel headers for your target system must be installed
CMake version at least 3.12 is required; cmake-2.x in CentOS7 will fail.
```shell script
yum install gcc cmake3 kernel-devel
```

### Build & Run
This kernel module is designed to be compiled out-of-source and can be built
with the following steps:
```shell script
mkdir src/build
cd src/build
cmake -DLOCAL_BUILD=yes -DKERNEL_NAME=$(uname -r) ..
make
```
You must have the kernel headers installed for any version you are targeting.
* `KERNEL_NAME` is exposed to allow for compiling an alternate kernel
  that's available on your system.
* `LOCAL_BUILD` ignores the calls to our internal build utility, which
  essentially wraps the provided build procedure in some packaging steps.