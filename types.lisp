(in-package :cleek)

(setf *read-default-float-format* 'double-float)

(defvar *zeek-set-separator* #\,)
(defvar *zeek-unset-field* #\-)
(defvar *zeek-empty-field* "(empty)")

(defun string->keyword (s) (ax:make-keyword (str:upcase s)))
(defun keyword->string (k) (str:downcase (string k)))

(defvar *zeek-open-close-time-format* '(:year "-" (:month 2) "-" (:day 2) "-" (:hour12 2) "-" (:min 2) "-" (:sec 2))
  "Time format for #open and #close sections of Zeek format header and footer.")

(defun timestamp-to-zeek-open-close-string (ts)
  (local-time:format-timestring nil ts :format *zeek-open-close-time-format* :timezone local-time:+utc-zone+))

(defun timestamp-to-zeek-ts-string (ts)
  (format nil "~d.~6,'0d" (local-time:timestamp-to-unix ts) (local-time:nsec-of ts)))

(defun zeek-ts-string-to-timestamp (s)
  (destructuring-bind (secs nsecs) (mapcar #'parse-integer (str:split #\. s))
    (local-time:unix-to-timestamp secs :nsec nsecs)))

;; type conversions between zeek, JSON, and lisp.
(defparameter *zeek-primitive-type-parsers*
  `((:bool . ,(lambda (x) (if (string= "T" x) t nil)))
    (:count . ,#'parse-integer)
    (:int . ,#'parse-integer)
    (:double . ,#'read-from-string)
    (:time . ,#'zeek-ts-string-to-timestamp)
    (:interval . ,#'read-from-string)
    (:string . ,#'identity) ; or #'string maybe?
    (:port . ,#'parse-integer)
    (:addr . ,#'na:make-ip-address)
    (:subnet . ,#'na:make-ip-network)
    (:enum . ,#'identity) ; just keep it as a string i suppose
    ))

(defparameter *zeek-stringify*
  `((:bool . ,(lambda (x) (if x "T" "F")))
    (:count . ,#'write-to-string)
    (:int . ,#'write-to-string)
    (:double . ,(lambda (x) (format nil "~,6f" x)))
    (:time . ,#'timestamp-to-zeek-ts-string)
    (:interval . ,(lambda (x) (format nil "~,6f" x)))
    (:string . ,#'identity)
    (:port . ,#'string)
    (:addr . ,(lambda (x) (str:downcase (na:str x))))
    (:subnet . ,(lambda (x) (str:downcase (na:str x))))
    (:enum . ,#'identity)))

;; TODO: might be premature optimization, but maybe:
;; check for unset/empty
;; check for primitive-type with when-let
;; then do check for aggregates.
(defun parse-zeek-type (field type)
  (let ((type-string (keyword->string type)))
    (cond ((or (string= field (string *zeek-unset-field*))
               (string= field (string *zeek-empty-field*)))
           field)
          ((or (str:starts-with? "set" type-string)
               (str:starts-with? "vector" type-string))
           (cl-ppcre:register-groups-bind (nil primitive-type) 
               ("(set|vector)\\[(.*?)\\]" type-string)
             (mapcar (lambda (f) (parse-zeek-type f (string->keyword primitive-type)))
                     (str:split *zeek-set-separator* field))))
          (t (funcall (ax:assoc-value *zeek-primitive-type-parsers* type) field)))))

(defun unparse-zeek-type (field type)
  (let ((type-string (keyword->string type)))
    (cond ((stringp field)
           field)
          ((or (str:starts-with? "set" type-string)
               (str:starts-with? "vector" type-string))
           (cl-ppcre:register-groups-bind (nil primitive-type) 
               ("(set|vector)\\[(.*?)\\]" type-string)
             (str:join *zeek-set-separator*
                       (mapcar (lambda (f) (unparse-zeek-type f (string->keyword primitive-type)))
                               field))))
          (t (funcall (ax:assoc-value *zeek-stringify* type) field)))))

;; TODO: in order to properly support JSON->Zeek transforms, you'll need to have a map of all
;; possible field names to the zeek types, which kinda sucks. does that matter? unclear.
