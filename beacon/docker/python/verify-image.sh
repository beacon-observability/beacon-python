#!/usr/bin/env bash
set -euo pipefail
image=${1:?image required}
version=${2:?version required}
here=$(cd -- "$(dirname -- "$0")" && pwd)
[[ $(docker image inspect "$image" --format '{{.Config.User}}') == '65532:65532' ]]
[[ $(docker image inspect "$image" --format '{{index .Config.Labels "org.opencontainers.image.version"}}') == "$version" ]]
docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges --network=none \
  --tmpfs /tmp:rw,nosuid,nodev,size=128m --mount "type=bind,src=$here,dst=/fixture,readonly" \
  "$image" python /fixture/smoke.py "$version"
