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

(defparameter *pinned-deps* '("netaddr" "cl-dns" "cl-tld")
  "Systems CI checks out from git and expects ASDF to resolve to those
checkouts. All three are also in the quicklisp dist, so when the source registry
does not reach the checkouts, quicklisp quietly supplies a dist release instead
and nothing complains until a symbol moves. That is what happened: cleek was
built against netaddr-20260101-git, eight months behind the MAKE-IP-LIKE that
helpers.lisp needs.")

(defun %dist-release-p (directory)
  "True when DIRECTORY is a quicklisp dist release
(<quicklisp>/dists/<dist>/software/<release>/) rather than a checkout."
  (search "/dists/" (namestring directory)))

(defun check-pinned-deps ()
  "Report where each of *PINNED-DEPS* resolved and refuse a quicklisp dist
release. The paths are printed unconditionally so that the next surprise is one
grep of the job log away rather than invisible."
  (let ((substituted '()))
    (dolist (name *pinned-deps*)
      (let ((directory (asdf:system-source-directory name)))
        (format t "~&cleek-ci: ~a <- ~a~%" name directory)
        (when (%dist-release-p directory)
          (push (list name directory) substituted))))
    (finish-output)
    (when substituted
      (error "pinned dependenc~@P resolved to a quicklisp dist release instead ~
of a checkout: ~{~a (~a)~^, ~}. Check CL_SOURCE_REGISTRY."
             (length substituted)
             (reduce #'append (reverse substituted))))))

(defun load-deps ()
  "Quickload what the test and build targets need."
  (with-fatal-conditions
    (uiop:symbol-call :ql :quickload (list "cleek" "fiveam"))
    (check-pinned-deps))
  (uiop:quit 0 t))

(defun test ()
  "Run the test suites. CLEEK/TESTS' TEST-OP signals on any fiveam failure, so a
red suite lands in WITH-FATAL-CONDITIONS and exits nonzero."
  (with-fatal-conditions
    (asdf:load-system :cleek)
    (check-pinned-deps)
    (asdf:test-system :cleek))
  (uiop:quit 0 t))

(defun build ()
  "Dump the executable. ASDF's IMAGE-OP ends in SAVE-LISP-AND-DIE, so this
normally exits before returning; the Makefile is what verifies that a working
bin/cleek actually appeared."
  (with-fatal-conditions
    (asdf:load-system :cleek)
    (check-pinned-deps)
    (asdf:make :cleek))
  (uiop:quit 0 t))
