#!/bin/bash

if type update-alternatives 2>/dev/null >&1; then
    # Remove previous link if it doesn't use update-alternatives
    if [ -L '/usr/bin/${executable}' -a -e '/usr/bin/${executable}' -a "`readlink '/usr/bin/${executable}'`" != '/etc/alternatives/${executable}' ]; then
        rm -f '/usr/bin/${executable}'
    fi
    update-alternatives --install '/usr/bin/${executable}' '${executable}' '/opt/${sanitizedProductName}/${executable}' 100 || ln -sf '/opt/${sanitizedProductName}/${executable}' '/usr/bin/${executable}'
else
    ln -sf '/opt/${sanitizedProductName}/${executable}' '/usr/bin/${executable}'
fi

# Check if user namespaces are supported by the kernel and working with a quick test:
if ! { [[ -L /proc/self/ns/user ]] && unshare --user true; }; then
    # Use SUID chrome-sandbox only on systems without user namespaces:
    chmod 4755 '/opt/${sanitizedProductName}/chrome-sandbox' || true
else
    chmod 0755 '/opt/${sanitizedProductName}/chrome-sandbox' || true
fi

if hash update-mime-database 2>/dev/null; then
    update-mime-database /usr/share/mime || true
fi

if hash update-desktop-database 2>/dev/null; then
    update-desktop-database /usr/share/applications || true
fi

# Ubuntu 24.04+ blocks unprivileged user namespaces unless an AppArmor profile allows them, and
# Electron's sandbox needs one. Same approach as Chrome and VS Code: a profile for Ajar only.
if [ -d /etc/apparmor.d ] && [ -f /etc/apparmor.d/abi/4.0 ]; then
    cat > /etc/apparmor.d/ajar <<'PROFILE'
abi <abi/4.0>,
include <tunables/global>

profile ajar /opt/${sanitizedProductName}/${executable} flags=(unconfined) {
  userns,

  include if exists <local/ajar>
}
PROFILE
    if hash apparmor_parser 2>/dev/null; then
        apparmor_parser --replace --write-cache --skip-read-cache /etc/apparmor.d/ajar || true
    fi
fi
