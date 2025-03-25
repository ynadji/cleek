build:
	ros run --eval "(progn (asdf:make :cleek) (quit))"

coverage:
	sbcl --load coverage.lisp

test:
	ros run --eval "(progn (asdf:test-system :cleek) (quit))"

.PHONY: docs
docs:
	ros run --eval "(ql:quickload :staple-markdown)" --eval "(staple:generate :cleek :if-exists :supersede)" --eval "(quit)"
