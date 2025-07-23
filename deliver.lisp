(in-package cl-user)

(load-all-patches)

(require "asdf")

(let ((quicklisp-init (merge-pathnames "quicklisp/setup.lisp" (user-homedir-pathname))))
  (when (probe-file quicklisp-init)
    (load quicklisp-init)))

(set-default-character-element-type 'character)

(asdf:load-system :cleek)

(let* ((version (asdf:system-version (asdf:find-system :cleek)))
       (src-dir (asdf:system-source-directory :cleek)))
  (deliver #'cleek:main
           "cleek.lw"
           0
           :editor-style :emacs))
