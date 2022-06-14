#!/usr/bin/env bash
set -eux

docker create --name generate-rpmdb-fixture centos:8 sh -c 'tail -f /dev/null'

function cleanup {
  docker kill generate-rpmdb-fixture
  docker rm generate-rpmdb-fixture
}
trap cleanup EXIT

docker start generate-rpmdb-fixture
docker exec -i --tty=false generate-rpmdb-fixture bash <<-EOF
  mkdir -p /scratch
  cd /scratch
  rpm --initdb --dbpath /scratch
  curl -sSLO https://github.com/wagoodman/dive/releases/download/v0.9.2/dive_0.9.2_linux_amd64.rpm
  rpm --dbpath /scratch -ivh dive_0.9.2_linux_amd64.rpm
  rm dive_0.9.2_linux_amd64.rpm
  rpm --dbpath /scratch -qa
EOF

docker cp generate-rpmdb-fixture:/scratch/Packages .

docker build -o . - <<EOF
FROM mcr.microsoft.com/cbl-mariner/distroless/base:2.0 as base
FROM scratch
COPY --from=base /var/lib/rpmmanifest/container-manifest-2 .
EOF
