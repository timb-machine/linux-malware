# Carbon Black BPF Probe
This package contains the source for the eBPF-based event collection probe used by the 
Carbon Black Cloud Linux agent. The probe is built atop the [iovisor/bcc](https://github.com/iovisor/bcc)
project, which provides the infrastructure for compiling and inserting BPF applications.

## Building the Probe
### Prerequisites
Because the probe is built using the [iovisor/bcc](https://github.com/iovisor/bcc) project, 
`bcc` and its dependencies must be installed on the target system that the probe will be
built on. See the [installation](https://github.com/iovisor/bcc/blob/master/INSTALL.md) documentation
from `bcc` for the steps to install `bcc` and its dependencies on the target build system.

### Build
The following commands will produce the `bpf-probe` shared library for consumption, as well as a
short `check_probe` application to verify the probe runs on the target system.
```shell
mkdir src/build && cd src/build
cmake -DLOCAL_BUILD=yes ..
make
```

### Test
On success, `check_probe` should finish with a `0` exit code.
```shell
sudo ./check_probe
echo $?
```

