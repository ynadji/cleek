build:
	sbcl --eval "(progn (asdf:make :cleek) (quit))"

build-ros:
	ros run --eval "(progn (asdf:make :cleek) (quit))"

coverage:
	sbcl --load coverage.lisp

test:
	time sbcl --eval "(progn (asdf:test-system :cleek) (quit))"

.PHONY: docs
docs:
	sbcl --eval "(ql:quickload :staple-markdown)" --eval "(staple:generate :cleek :if-exists :supersede)" --eval "(quit)"
