#!/bin/sh
set -eu
# OpenSSH requires an authorized-keys file owned by root or the target account.
# A bind mount retains the host user's ownership, which need not match either.
install -o root -g root -m 0644 /run/demo_authorized_keys /etc/ssh/demo_authorized_keys
exec "$@"
