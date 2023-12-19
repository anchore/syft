#!/bin/bash
set -eu -o pipefail

DESTINATION_DIR="bin"

curate_destination() {
      organization_name=$1
      binary_name=$2
      version=$3
      arch=$4

      # translate all / into -
      arch=$(echo $arch | tr '/' '-')

      # Create directory and define file path
      dir_path="${DESTINATION_DIR}/${organization_name}-${version}/${arch}"
      mkdir -p "$dir_path"
      file_path="${dir_path}/${binary_name}"

      echo $file_path
}

# function to get a binary from a container
docker_copy_binary() {
    local image=$1
    local platform=$2
    local binary_path=$3
    local binary_name=$4
    local version=$5
    local organization_name=${6:-$binary_name}


    file_path=$(curate_destination $organization_name $binary_name $version $platform)

    # Check if the file already exists
    if [ -f "$file_path" ]; then
        echo "...$file_path already exists (skipping)"
        return
    fi

    echo "Pulling $image..."
    docker pull "$image" --platform $platform -q

    container_id=$(docker create "$image")

    echo "  - copying $binary_path to $file_path..."
    docker cp "$container_id:$binary_path" "$file_path" -q

    docker rm "$container_id"
}


# let's download stuff!

docker_copy_binary \
  busybox:1.36.1@sha256:058f0df5310fbbbfea7e81a3a3e2b4bf3452438ec841138d170e170adbbd27a4 linux/amd64 /bin/busybox \
  busybox 1.36.1

docker_copy_binary \
  bash:5.1.16@sha256:c7a903a541d8f5fe693cbe7f5ece18a1b6a03734c76092d2b153d7e98a964927 linux/amd64 /usr/local/bin/bash \
  bash 5.1.16

docker_copy_binary \
  erlang:25.3.2.6@sha256:0d1e530ec0e8047094f0a1d841754515bad9b0554260a3147fb34df31b3064fe linux/amd64 /usr/local/lib/erlang/bin/erl \
  erlang 25.3.2.6

docker_copy_binary \
  golang:1.21.3@sha256:3ce8313c3513515040870c55e0c041a2b94f3576a58cfd3948633604214aa811 linux/amd64 /usr/local/go/bin/go \
  go 1.21.3

docker_copy_binary \
  haproxy:1.5.14@sha256:3d57e3921cc84e860f764e863ce729dd0765e3d28d444775127bc42d68f98e10 linux/amd64 /usr/local/sbin/haproxy \
  haproxy 1.5.14

docker_copy_binary \
  haproxy:1.8.22@sha256:acd6d3feb77b3f50e672427756b1375fa479b8aeaf30823051e811d10b98da3f linux/amd64 /usr/local/sbin/haproxy \
  haproxy 1.8.22

docker_copy_binary \
  haproxy:2.7.3@sha256:17d8aa6bf16882a294bdcccc757dd4002045f34b719e9f94dfd4801614801aea linux/amd64 /usr/local/sbin/haproxy \
  haproxy 2.7.3

docker_copy_binary \
  httpd:2.4.54@sha256:c13feaef62bdb03e65e645f47d9780adea5a080c78eb9e4b3c32e861327262b4 linux/amd64 /usr/local/apache2/bin/httpd \
  httpd 2.4.54

docker_copy_binary \
  ibmjava:8@sha256:05ef6b0f754aa3a8cebcec36260a70c234a217b21240a998604f33459037bc08 linux/amd64 /opt/ibm/java/jre/bin/java \
  java 1.8.0_391 java-jre-ibm

docker_copy_binary \
  mariadb:10.6.15@sha256:92d499d9e02e92dc55c8160ef4004aa07f2e835197b18864ed214ca441e0dcfc linux/amd64 /usr/sbin/mariadbd \
  mariadb 10.6.15

docker_copy_binary \
  memcached:1.6.18@sha256:9af8e788d5f7f4dc82fd49cf4a7efff1a0b5b4673085bc88f3ccb8a1c772ab3e linux/amd64 /usr/local/bin/memcached \
  memcached 1.6.18

docker_copy_binary \
  mysql:5.6.51@sha256:897086d07d1efa876224b147397ea8d3147e61dd84dce963aace1d5e9dc2802d linux/amd64 /usr/sbin/mysqld \
  mysql 5.6.51

docker_copy_binary \
  mysql:8.0.34@sha256:8b8835a2c32cd7357a5d2ea4b49ad870ff519c8c1d4add362803feddf4a0a973 linux/amd64 /usr/sbin/mysqld \
  mysql 8.0.34

docker_copy_binary \
  nginx:1.25.1@sha256:73e957703f1266530db0aeac1fd6a3f87c1e59943f4c13eb340bb8521c6041d7 linux/amd64 /usr/sbin/nginx \
  nginx 1.25.1

docker_copy_binary \
  openresty/openresty:1.21.4.3-2-alpine-fat@sha256:9f9b9d86f2a0f903b1226c3e8a6790293cbb58e521a186ac0031a030ea42c39b linux/amd64 /usr/local/openresty/nginx/sbin/nginx \
  nginx 1.21.4.3 nginx-openresty

docker_copy_binary \
  node:19.2.0@sha256:9bf5846b28f63acab0ccb0a39a245fbc414e6b7ecd467282f58016537c06e159 linux/amd64 /usr/local/bin/node \
  node 19.2.0

echo "Done!"
tree $DESTINATION_DIR
