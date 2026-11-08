#!/bin/bash

# Delete the link to the binary
if type update-alternatives >/dev/null 2>&1; then
    update-alternatives --remove '${executable}' '/usr/bin/${executable}'
else
    rm -f '/usr/bin/${executable}'
fi

# Remove Ajar's AppArmor profile (see after-install).
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    if [ -f /etc/apparmor.d/ajar ]; then
        if hash apparmor_parser 2>/dev/null; then apparmor_parser --remove /etc/apparmor.d/ajar 2>/dev/null || true; fi
        rm -f /etc/apparmor.d/ajar
    fi
fi
