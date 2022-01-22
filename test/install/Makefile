PORT=8000
SERVE_CMD=python3 -m http.server --directory ../../snapshot $(PORT)

test:
	@for f in $(shell ls *_test.sh); do echo "Running test suite '$${f}'"; bash $${f} || exit 1; done

serve-snapshot:
	$(SERVE_CMD)