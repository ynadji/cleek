(in-package :cleek)

(defvar *input-format* :zeek) ; or :json
(defvar *output-format* :zeek) ; or :json

(defvar *input-compression* :txt) ; or :zstd or :gzip
(defvar *output-compression* :txt) ; or :zstd or :gzip

(defvar *zeek-field-separator* #\Tab)
(defvar *zeek-set-separator* #\,)
(defvar *zeek-unset-field #\-)

(defun infer-log-format (stream)
  (ecase (peek-char nil stream)
    (#\{ :json)
    (#\# :zeek)))

(defun ->keyword (s) (ax:make-keyword (str:upcase s)))

(defun read-zeek-header (stream)
  (let ((field-names nil)
        (types nil))
    (loop while (eq #\# (peek-char nil stream))
          for line = (read-line stream nil)
          when (str:starts-with? "#fields" line)
            do (setf field-names (mapcar #'->keyword (rest (str:split *zeek-field-separator* line))))
          when (str:starts-with? "#types" line)
            do (setf types (mapcar #'->keyword (rest (str:split *zeek-field-separator* line)))))
    (values field-names types)))

(defun zeek-reader (stream field-names types)
  (declare (ignore types))
  (lambda ()
    (when (not (eq #\# (peek-char nil stream)))
      (let ((fields (str:split *zeek-field-separator* (read-line stream nil)))
            (ht (make-hash-table :size (length field-names))))
        (loop for field in fields for name in field-names
              do (setf (gethash name ht) field))
        ht))))

(defun json-reader (stream)
  (lambda ()
    (ax:when-let ((line (read-line stream nil)))
      (jzon:parse line :key-fn #'->keyword))))

(defun make-reader (stream)
  (ecase (infer-log-format stream)
    (:zeek (multiple-value-bind (field-names types) (read-zeek-header stream)
             (zeek-reader stream field-names types)))
    (:json (json-reader stream))))

;; TODO: In order to go from JSON input to Zeek output, I need to get the
;; FIELD-NAMES for the row with the most JSON keys.
(defun read-log (path)
  (with-open-file (in path)
    (let ((reader (make-reader in)))
      (loop for record = (funcall reader)
            while record
            collect record))))
