# HACKING.md

This file contains notes on how to test and run the project

## TPM testing

There are various ways to access the TPM:

### Rawdog the TPM device

This is the most straightforward way to access the TPM, you will have to compile the project and run the binary as root or set up some rules to allow user access to the device.

```
sudo TCTI=device:/dev/tpmrm0 ./target/debug/<TEST_BIN_PATH>
```

### Using a TPM emulator

You can test using a TPM emulator such as [swtpm](https://github.com/stefanberger/swtpm). A justfile action to start a swtpm instance is provided in the project.

```
just swtpm
```

Set the TCTI to `swtpm`, and then run the binary.

```
TCTI=swtpm ./target/debug/<TEST_BIN_PATH>
```

### Using `tpm2-abrmd`

This is the most recommended way to access the TPM on desktop Linux systems, as it provides a D-Bus interface to the TPM.

You may install it using your package manager, for example on Fedora:

```
sudo dnf install tpm2-abrmd
```

Then activate the service:

```
sudo systemctl enable --now tpm2-abrmd
```

You may also want to configure D-Bus to allow yourself (or people in a specific group), by editing D-Bus policies (You shouldn't ship these configs to production, rewrite them to limit access to just your app)

```
sudo nano /etc/dbus-1/system.d/tpm2-abrmd.conf
```

Give only yourself access to the API:

```xml
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <policy user="yourusername">
    <allow own="com.intel.tss2.Tabrmd"/>
    <allow send_destination="com.intel.tss2.Tabrmd"/>
    <allow send_interface="com.intel.tss2.Tabrmd"/>
  </policy>
</busconfig>
```

Give people in the `tss` group access to the API:

```xml
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <policy group="tss">
    <allow own="com.intel.tss2.Tabrmd"/>
    <allow send_destination="com.intel.tss2.Tabrmd"/>
    <allow send_interface="com.intel.tss2.Tabrmd"/>
  </policy>
</busconfig>
```

You may also want to use this policy instead:

```xml
<busconfig>
    <policy group="tss">
        <allow send_destination="com.intel.tss2.Tabrmd"/>
        <allow send_interface="com.intel.tss2.Tabrmd"/>
    </policy>
</busconfig>
```

You may also want to create some Polkit actions and rules to control access to the TPM.

