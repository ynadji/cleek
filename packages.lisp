(in-package :cl-user)
(defpackage :cleek
  (:use :cl)
  (:local-nicknames (:ax :alexandria))
  (:export :valid-domain? :registerable-domain? :make-trie :contains-domain? :normalize-domain :without-normalization))
