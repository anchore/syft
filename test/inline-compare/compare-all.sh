#!/usr/bin/env bash
set -eu

images=("debian:10.5" "centos:8.2.2004" "rails:5.0.1" "alpine:3.12.0" "anchore/test_images:java" "anchore/test_images:py38" "anchore/anchore-engine:v0.8.2" "jenkins/jenkins:2.249.2-lts-jdk11" )

# gather all image analyses
for img in "${images[@]}"; do
    echo "Gathering facts for $img"
    COMPARE_IMAGE=${img} make gather-image
done

# compare all results
for img in "${images[@]}"; do
    echo "Comparing results for $img"
    COMPARE_IMAGE=${img} make compare-image
done
