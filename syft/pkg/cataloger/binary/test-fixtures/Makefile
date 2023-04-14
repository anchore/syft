.PHONY: all
all: \
	classifiers/dynamic/python-binary-shared-lib-3.11 \
	classifiers/dynamic/python-binary-shared-lib-redhat-3.9 \
	classifiers/dynamic/python-binary-with-version-3.9 \
	classifiers/dynamic/python-binary-3.4-alpine \
	classifiers/dynamic/ruby-library-3.2.1 \
	classifiers/dynamic/ruby-library-2.7.7 \
	classifiers/dynamic/ruby-library-2.6.10 \
	classifiers/dynamic/argocd-2.5.11 \
	classifiers/dynamic/argocd-2.6.4 \
	classifiers/dynamic/helm-3.11.1 \
	classifiers/dynamic/helm-3.10.3 \
	classifiers/dynamic/kubectl-1.24.11 \
	classifiers/dynamic/kubectl-1.25.7 \
	classifiers/dynamic/kubectl-1.26.2 \
	classifiers/dynamic/kustomize-4.5.7 \
	classifiers/dynamic/kustomize-5.0.0 \
	classifiers/dynamic/consul-1.15.2



classifiers/dynamic/python-binary-shared-lib-3.11:
	$(eval $@_image := "python:3.11-slim@sha256:0b106e1d2bf485c2a41474bc9cd5103e9eea4e179f40f10741b53b127059221e")
	./get-image-file.sh $($@_image) \
		/usr/local/bin/python3.11 \
		$@/python3
	./get-image-file.sh $($@_image) \
		/usr/local/lib/libpython3.11.so.1.0 \
		$@/libpython3.11.so.1.0

classifiers/dynamic/python-binary-shared-lib-redhat-3.9:
	$(eval $@_image := "registry.access.redhat.com/ubi8/python-39@sha256:f3cf958b96ce016b63e3e163e488f52e42891304dafef5a0811563f22e3cbad0")
	./get-image-file.sh $($@_image) \
		/usr/bin/python3.9 \
		$@/python3.9
	./get-image-file.sh $($@_image) \
		/usr/lib64/libpython3.9.so.1.0 \
		$@/libpython3.9.so.1.0

classifiers/dynamic/python-binary-with-version-3.9:
	$(eval $@_image := "python:3.9.16-bullseye@sha256:93fb93c461a2e47a2176706fad1f39eaacd5dd40e19c0b018699a28c03eb2e2a")
	./get-image-file.sh $($@_image) \
		/usr/bin/python3.9 \
		$@/python3.9

classifiers/dynamic/python-binary-3.4-alpine:
	$(eval $@_image := "python:3.4-alpine@sha256:c210b660e2ea553a7afa23b41a6ed112f85dbce25cbcb567c75dfe05342a4c4b")
	./get-image-file.sh $($@_image) \
		/usr/local/bin/python3.4 \
		$@/python3.4
	./get-image-file.sh $($@_image) \
		/usr/local/lib/libpython3.4m.so.1.0 \
		$@/libpython3.4m.so.1.0

classifiers/dynamic/ruby-library-3.2.1:
	$(eval $@_image := "ruby:3.2.1-bullseye@sha256:b4a140656b0c5d26c0a80559b228b4d343f3fdbf56682fcbe88f6db1fa9afa6b")
	./get-image-file.sh $($@_image) \
		/usr/local/bin/ruby \
		$@/ruby
	./get-image-file.sh $($@_image) \
		/usr/local/lib/libruby.so.3.2.1 \
		$@/libruby.so.3.2.1
	./get-image-file.sh $($@_image) \
		/usr/local/lib/libruby.so.3.2 \
		$@/libruby.so.3.2

classifiers/dynamic/ruby-library-2.7.7:
	$(eval $@_image := "ruby:2.7.7-bullseye@sha256:055191740a063f33fef1f09423e5ed8f91143aae62a3772a90910118464c5120")
	./get-image-file.sh $($@_image) \
		/usr/local/bin/ruby \
		$@/ruby
	./get-image-file.sh $($@_image) \
		/usr/local/lib/libruby.so.2.7.7 \
		$@/libruby.so.2.7.7
	./get-image-file.sh $($@_image) \
		/usr/local/lib/libruby.so.2.7 \
		$@/libruby.so.2.7

classifiers/dynamic/ruby-library-2.6.10:
	$(eval $@_image := "ruby:2.6.10@sha256:771a810704167e55da8a19970c5dfa6eb795dfee32547adffa29ea72703f7243")
	./get-image-file.sh $($@_image) \
		/usr/local/bin/ruby \
		$@/ruby
	./get-image-file.sh $($@_image) \
		/usr/local/lib/libruby.so.2.6.10 \
		$@/libruby.so.2.6.10
	./get-image-file.sh $($@_image) \
		/usr/local/lib/libruby.so.2.6 \
		$@/libruby.so.2.6

classifiers/dynamic/argocd-2.5.11:
	$(eval $@_image := "argoproj/argocd:v2.5.11@sha256:d1062935b3256ec69422843ebcb50debb54fd389436961586000c8ce6ee7f249")
	./get-image-file.sh $($@_image) \
		/usr/local/bin/argocd \
		$@/argocd

classifiers/dynamic/argocd-2.6.4:
	$(eval $@_image := "argoproj/argocd:v2.6.4@sha256:61fcbba187ff53c00696cb580edf70cada59c45cf399d8477631acf43cf522ee")
	./get-image-file.sh $($@_image) \
		/usr/local/bin/argocd \
		$@/argocd

classifiers/dynamic/helm-3.11.1:
	$(eval $@_image := "alpine/helm:3.11.1@sha256:8628e3695fb743a8b9de89626f1b7a221280c2152c0e288c2504e59b68233e8b")
	./get-image-file.sh $($@_image) \
		/usr/bin/helm \
		$@/helm

classifiers/dynamic/helm-3.10.3:
	$(eval $@_image := "argoproj/argocd:v2.6.4@sha256:61fcbba187ff53c00696cb580edf70cada59c45cf399d8477631acf43cf522ee")
	./get-image-file.sh $($@_image) \
		/usr/local/bin/helm \
		$@/helm

classifiers/dynamic/kubectl-1.24.11:
	$(eval $@_image := "bitnami/kubectl:1.24.11@sha256:79d60c5ac8a1dc84e2c39f56d8e8cc0053159b5ed88f283bdf8fbda1ee86c8bc")
	./get-image-file.sh $($@_image) \
		/opt/bitnami/kubectl/bin/kubectl \
		$@/kubectl

classifiers/dynamic/kubectl-1.25.7:
	$(eval $@_image := "bitnami/kubectl:1.25.7@sha256:d7b00dbfdc6d8890aefe40edfb6c1d4c90cbb6c978794bb51a21744edc34ba7a")
	./get-image-file.sh $($@_image) \
		/opt/bitnami/kubectl/bin/kubectl \
		$@/kubectl

classifiers/dynamic/kubectl-1.26.2:
	$(eval $@_image := "line/kubectl-kustomize:1.26.2-5.0.0@sha256:9ee3b4a9a21f0777fc1d8c64208290f818a2e68c5e9e892e931621bda089bf06")
	./get-image-file.sh $($@_image) \
		/usr/local/bin/kubectl \
		$@/kubectl

classifiers/dynamic/kustomize-4.5.7:
	$(eval $@_image := "argoproj/argocd:v2.6.4@sha256:61fcbba187ff53c00696cb580edf70cada59c45cf399d8477631acf43cf522ee")
	./get-image-file.sh $($@_image) \
		/usr/local/bin/kustomize \
		$@/kustomize

classifiers/dynamic/kustomize-5.0.0:
	$(eval $@_image := "line/kubectl-kustomize:1.26.2-5.0.0@sha256:9ee3b4a9a21f0777fc1d8c64208290f818a2e68c5e9e892e931621bda089bf06")
	./get-image-file.sh $($@_image) \
		/usr/local/bin/kustomize \
		$@/kustomize

classifiers/dynamic/consul-1.15.2:
	$(eval $@_image := "hashicorp/consul:1.15.2@sha256:c2169f3bb18dd947ae8eb5f6766896695c71fb439f050a3343e0007d895615b8")
	./get-image-file.sh $($@_image) \
		/bin/consul \
		$@/consul

.PHONY: clean
clean:
	rm -rf classifiers/dynamic

.PHONY: cache.fingerprint
cache.fingerprint: # for CI
	$(title,Install test fixture fingerprint)
	@find ./classifiers/dynamic/* -type f -exec md5sum {} + | awk '{print $1}' | sort | tee /dev/stderr | md5sum | tee cache.fingerprint >> cache.fingerprint
