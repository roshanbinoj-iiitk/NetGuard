#!/usr/bin/env bash
# Run lab commands WITHOUT sudo, inside a private user + network + mount
# namespace where you appear as root. Nothing touches the host network,
# and everything disappears when the command exits.
#
#   lab/rootless.sh bash -c 'lab/setup.sh && lab/smoke.sh'
#   lab/rootless.sh bash          # interactive "root" shell for the lab
set -euo pipefail
[[ $# -gt 0 ]] || set -- bash
# `ip netns add` needs a writable /run/netns; give the private mount
# namespace its own empty /run.
exec unshare --user --map-root-user --net --mount --fork \
    bash -c 'mount -t tmpfs tmpfs /run && exec "$@"' rootless "$@"
