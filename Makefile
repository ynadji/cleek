# ci.lisp installs a debugger hook so that an unhandled condition exits nonzero
# instead of dropping to the debugger, reading EOF and exiting 0. See its header
# comment for how that made CI pass a build which never compiled anything.
LISP_CI = ros run --load ci.lisp --eval

.DEFAULT_GOAL := build
.PHONY: build deps test coverage deliver docs

# The rm matters: a failed build otherwise leaves the previous binary in place
# and the checks below pass on a stale artifact, which is what CI was uploading.
build:
	rm -f bin/cleek
	$(LISP_CI) "(cleek-ci:build)"
	@test -x bin/cleek || { echo "make build: no executable at bin/cleek" >&2; exit 1; }
	@./bin/cleek --version >/dev/null || { echo "make build: bin/cleek is not runnable" >&2; exit 1; }
	@echo "make build: $$(./bin/cleek --version)"

deps:
	$(LISP_CI) "(cleek-ci:load-deps)"

test:
	$(LISP_CI) "(cleek-ci:test)"

coverage:
	sbcl --load coverage.lisp

deliver:
	lw-console -build deliver.lisp

docs:
	ros run --eval "(ql:quickload :staple-markdown)" --eval "(staple:generate :cleek :if-exists :supersede)" --eval "(quit)"
