# cgroup v2

runc fully supports cgroup v2 (unified mode) since v1.0.0-rc93.

To use cgroup v2, you might need to change the configuration of the host init system.
Fedora (>= 31) uses cgroup v2 by default and no extra configuration is required.
On other systemd-based distros, cgroup v2 can be enabled by adding `systemd.unified_cgroup_hierarchy=1` to the kernel cmdline.

## Am I using cgroup v2?

Yes if `/sys/fs/cgroup/cgroup.controllers` is present.

## Host Requirements
### Kernel
* Recommended version: 5.2 or later
* Minimum version: 4.15

Kernel older than 5.2 is not recommended due to lack of freezer.

Notably, kernel older than 4.15 MUST NOT be used (unless you are running containers with user namespaces), as it lacks support for controlling permissions of devices.

### Systemd
On cgroup v2 hosts, it is highly recommended to run runc with the systemd cgroup driver (`runc --systemd-cgroup`), though not mandatory.

The recommended systemd version is 244 or later. Older systemd does not support a few features, including delegation of `cpuset` controller,
and some unit properties (`CPUQuotaPeriodSec`, `AllowedCPUs`, and `AllowedMemoryNodes`).

Make sure you also have the `dbus-user-session` (Debian/Ubuntu) or `dbus-daemon` (CentOS/Fedora) package installed, and that `dbus` is running. On Debian-flavored distros, this can be accomplished like so:

```console
$ sudo apt install -y dbus-user-session
$ systemctl --user start dbus
```

## Features

### Rootless
On cgroup v2 hosts, rootless runc can talk to systemd to get cgroup permissions to be delegated.

```console
$ runc spec --rootless
$ jq '.linux.cgroupsPath="user.slice:runc:foo"' config.json | sponge config.json
$ runc --systemd-cgroup run foo
```

The container processes are executed in a cgroup like `/user.slice/user-$(id -u).slice/user@$(id -u).service/user.slice/runc-foo.scope`.

#### Configuring delegation
Typically, only `memory` and `pids` controllers are delegated to non-root users by default.

```console
$ cat /sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/cgroup.controllers
memory pids
```

To allow delegation of other controllers, you need to change the systemd configuration as follows:

```console
# mkdir -p /etc/systemd/system/user@.service.d
# cat > /etc/systemd/system/user@.service.d/delegate.conf << EOF
[Service]
Delegate=cpu cpuset io memory pids
EOF
# systemctl daemon-reload
```

### Unified resource support

runc supports unified resources as per [runtime spec](https://github.com/opencontainers/runtime-spec/blob/master/config-linux.md#unified),
which is basically a way to directly specify cgroup parameters using cgroup
file names and the desired contents.  In case of systemd cgroup driver, runc
attempts to convert those parameters to systemd unit properties. Such conversion
is done on a best-effort basis, as systemd does not support all cgroup properties.
