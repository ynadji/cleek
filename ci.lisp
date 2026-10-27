;;;; Non-interactive entry points for the Makefile, and so for CI.
;;;;
;;;; ros/sbcl answer an unhandled condition by entering the interactive
;;;; debugger. With stdin at EOF -- every CI runner -- the debugger reads EOF,
;;;; unwinds to the toplevel REPL, reads EOF again, and exits 0. A build that
;;;; failed to compile a single file therefore reports success, and the job
;;;; happily uploads whatever stale bin/cleek was lying around. These entry
;;;; points turn anything that would reach the debugger into a nonzero exit.

(defpackage :cleek-ci
  (:use :cl)
  (:export #:load-deps #:test #:build))

(in-package :cleek-ci)

(defun %die (condition)
  (format *error-output* "~&cleek-ci: unhandled ~a: ~a~%" (type-of condition) condition)
  (ignore-errors (uiop:print-backtrace :stream *error-output* :count 25))
  (ignore-errors (finish-output *error-output*))
  (uiop:quit 1 t))

(defmacro with-fatal-conditions (&body body)
  "Run BODY so that any serious condition exits nonzero with a backtrace
instead of prompting a human who is not there.

HANDLER-BIND catches what gets signalled; the debugger hooks catch whatever
still reaches INVOKE-DEBUGGER (a BREAK, a condition resignalled from a handler).
Both hooks are bound dynamically rather than set globally, so SAVE-LISP-AND-DIE
does not capture them into the delivered binary -- cleek itself offers its
DROP-LINE/KEEP-LINE restarts interactively and must keep doing so."
  `(let* ((hook (lambda (condition &optional hook)
                  (declare (ignore hook))
                  (%die condition)))
          (*debugger-hook* hook)
          #+sbcl (sb-ext:*invoke-debugger-hook* hook))
     (declare (ignorable hook))
     (handler-bind ((serious-condition #'%die))
       ,@body)))

(defun load-deps ()
  "Quickload what the test and build targets need."
  (with-fatal-conditions
    (uiop:symbol-call :ql :quickload (list "cleek" "fiveam")))
  (uiop:quit 0 t))

(defun test ()
  "Run the test suites. CLEEK/TESTS' TEST-OP signals on any fiveam failure, so a
red suite lands in WITH-FATAL-CONDITIONS and exits nonzero."
  (with-fatal-conditions
    (asdf:test-system :cleek))
  (uiop:quit 0 t))

(defun build ()
  "Dump the executable. ASDF's IMAGE-OP ends in SAVE-LISP-AND-DIE, so this
normally exits before returning; the Makefile is what verifies that a working
bin/cleek actually appeared."
  (with-fatal-conditions
    (asdf:make :cleek))
  (uiop:quit 0 t))
