test-fixtures for https://github.com/anchore/syft/issues/1606

```sh
DEV_IMG=devalpine:3.17

docker build -t ${DEV_IMG} - <<EOF
FROM alpine:3.17
COPY --from=argoproj/argocd:v2.5.11 /usr/local/bin/argocd /bin/argocd-2.5.11
COPY --from=argoproj/argocd:v2.6.4 /usr/local/bin/argocd /bin/argocd-2.6.4
COPY --from=argoproj/argocd:v2.6.4 /usr/local/bin/helm /bin/helm-3.10.3
COPY --from=alpine/helm:2.16.10 /usr/bin/helm /bin/helm-2.16.10
COPY --from=argoproj/argocd:v2.6.4 /usr/local/bin/kustomize /bin/kustomize-4.5.7
COPY --from=line/kubectl-kustomize:1.26.2-5.0.0 /usr/local/bin/kustomize /bin/kustomize-5.0.0
COPY --from=bitnami/kubectl:1.24.11 /opt/bitnami/kubectl/bin/kubectl /bin/kubectl-1.24.11
COPY --from=bitnami/kubectl:1.25.7 /opt/bitnami/kubectl/bin/kubectl /bin/kubectl-1.25.7
COPY --from=line/kubectl-kustomize:1.26.2-5.0.0 /usr/local/bin/kubectl /bin/kubectl-1.26.2
EOF

TEMP_DIR=`mktemp -d`
docker run -u $(id -u):$(id -g) --workdir=/tmp -v=$TEMP_DIR:/tmp -i ${DEV_IMG} <<'EOF'
id
strings_save () {
  mkdir -p /tmp/$1
  strings /bin/$1 | grep $2 > /tmp/$1/$3
}
strings_save argocd-2.5.11 '2\.5\.11' argocd
strings_save argocd-2.6.4 '2\.6\.4' argocd
strings_save helm-2.16.10 '2\.16\.10' helm
strings_save helm-3.10.3 '3\.10\.3' helm
strings_save kustomize-4.5.7 '4\.5\.7' kustomize
strings_save kustomize-5.0.0 '5\.0\.0' kustomize
strings_save kubectl-1.24.11 '1\.24\.11' kubectl
strings_save kubectl-1.25.7 '1\.25\.7' kubectl
strings_save kubectl-1.26.2 '1\.26\.2' kubectl
EOF

echo tmp dir: $TEMP_DIR
ls -lah $TEMP_DIR
```