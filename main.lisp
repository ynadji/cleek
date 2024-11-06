(in-package :cleek)

(defvar *input-format* :zeek) ; or :json
(defvar *output-format* :zeek) ; or :json

(defvar *input-compression* :txt) ; or :zstd or :gzip
(defvar *output-compression* :txt) ; or :zstd or :gzip

(defvar *zeek-field-separator* #\Tab)
(defvar *zeek-set-separator* #\,)
(defvar *zeek-unset-field #\-)

(defparameter *buffer-size* (expt 2 9)) ; you'll want to bump this. also prob be vars
(defparameter *buffer* (make-array *buffer-size* :element-type '(unsigned-byte 8)))
(defvar *newline-byte* (char-code #\Newline))

(defun infer-log-format (stream)
  (ecase (peek-char nil stream)
    (#\{ :json)
    (#\# :zeek)))

(defun infer-compression (path)
  (cond ((str:ends-with? ".log" path :ignore-case t) :txt)
        ((str:ends-with? ".zst" path :ignore-case t) :zstd)
        ((str:ends-with? ".gz" path :ignore-case t) :gzip)))

(defun ->keyword (s) (ax:make-keyword (str:upcase s)))

(defun shift-unfinished-sequence (buf start)
  (let ((read-index (- (length buf) start)))
    (replace buf buf :start1 0 :start2 start)
    (fill buf 0 :start read-index)
    read-index))

(defun sequence-line-reader (stream)
  (let ((start 0)
        (eof? nil))
    (read-sequence *buffer* stream)
    (labels ((slr ()
               (when eof?
                 (return-from slr))
               (ax:if-let ((end (position *newline-byte* *buffer* :start start)))
                 (prog1 (babel:octets-to-string *buffer* :start start :end end)
                   (setf start (1+ end)))
                 (let ((read-index (shift-unfinished-sequence *buffer* start)))
                   ;; READ-SEQUENCE returns the first element of *BUFFER* that
                   ;; was unmodified. If it is equal to whatever the :START was,
                   ;; that means it read zero bytes and we hit EOF.
                   (setf eof? (= read-index (read-sequence *buffer* stream :start read-index)))
                   (setf start 0)
                   (slr)))))
      #'slr)))

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
;; FIELD-NAMES for the row with the most JSON keys. You could make the readers
;; return (VALUES ht MORE?) when you have a record and (VALUES FIELD-NAMES NIL)
;; when the file has finished being read.
(defun read-log (path)
  (with-open-file (in path)
    (let ((reader (make-reader in)))
      (loop for record = (funcall reader)
            while record
            collect record))))

;; well, looks like everything is gonna have to be with READ-SEQUENCE and
;; streams of bytes.
(defun read-from-gzip ()
  (with-open-file (in #P"/Users/yacin/code/cleek/data/json/gzip/dns.log.gz" :element-type '(unsigned-byte 8)) 
    (let ((stream (chipz:make-decompressing-stream 'chipz:gzip in))
          (buffer (make-array 64 :element-type '(unsigned-byte 8))))
      (read-sequence buffer stream)
      buffer)))

(defun read-from-zstd ()
  (with-open-file (in #P"/Users/yacin/code/cleek/data/json/zstd/dns.log.zst" :element-type '(unsigned-byte 8)) 
    (let ((stream (zstd:make-decompressing-stream in))
          (buffer (make-array 64 :element-type '(unsigned-byte 8))))
      (read-sequence buffer stream)
      buffer)))
