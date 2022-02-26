TARGET=../.goreleaser.yaml

.PHONY: snapshot-config
snapshot-config:
	cat snapshot.yaml > $(TARGET)
	cat env-skip-signing.yaml >> $(TARGET)
	cat main.yaml >> $(TARGET)
	cat docker.yaml >> $(TARGET)
	cat $(TARGET)

.PHONY: snapshot-with-signing-config
snapshot-with-signing-config:
	# we leave out docker entirely such that this can easily be tested in CI
	cat snapshot.yaml > $(TARGET)
	cat env-default.yaml >> $(TARGET)
	cat main.yaml >> $(TARGET)
	cat $(TARGET)

.PHONY: release-config
release-config:
	cat env-default.yaml > $(TARGET)
	cat docker.yaml >> $(TARGET)
	cat main.yaml >> $(TARGET)
	cat $(TARGET)
