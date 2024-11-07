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

(defun ->keyword (s) (ax:make-keyword (str:upcase s)))

(defun shift-unfinished-sequence (buf start)
  (let ((read-index (- (length buf) start)))
    (replace buf buf :start1 0 :start2 start)
    (fill buf 0 :start read-index)
    read-index))

(defun sequence-line-reader (stream)
  (let ((start 0)
        (eof? nil)
        (first-byte (setf (aref *buffer* 0)
                          (read-byte stream nil))))
    (read-sequence *buffer* stream :start 1) ; we already read the first byte above.
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
                   (setf eof? (= read-index
                                 (read-sequence *buffer* stream :start read-index)))
                   (setf start 0)
                   (slr)))))
      (values #'slr
              (ecase first-byte ; 123 is (char-code #\{), 35 is (char-code #\#)
                (123 :json)
                (35 :zeek))))))

(defun read-zeek-header (line-reader)
  (let ((field-names nil)
        (types nil)
        (more-header? t))
    (loop while more-header?
          for line = (funcall line-reader)
          when (str:starts-with? "#fields" line)
            do (setf field-names (mapcar #'->keyword (rest (str:split *zeek-field-separator* line))))
          when (str:starts-with? "#types" line)
            do (setf types (mapcar #'->keyword (rest (str:split *zeek-field-separator* line)))
                     more-header? nil))
    (values field-names types)))

(defun zeek-reader (line-reader field-names types)
  (declare (ignore types))
  (let ((num-fields (length field-names)))
   (lambda ()
     (let ((line (funcall line-reader))
           (ht (make-hash-table :size num-fields)))
       (unless (or (not line)
                   (char= #\# (char line 0)))
        (loop for field in (str:split *zeek-field-separator* line)
              for name in field-names
              do (setf (gethash name ht) field)))
       (unless (zerop (hash-table-count ht))
         ht)))))

(defun json-reader (line-reader)
  (lambda ()
    (ax:when-let ((line (funcall line-reader)))
      (jzon:parse line :key-fn #'->keyword))))

(defun make-reader (stream)
  (multiple-value-bind (line-reader format) (sequence-line-reader stream)
    (ecase format
      (:zeek (multiple-value-bind (field-names types) (read-zeek-header line-reader)
               (zeek-reader line-reader field-names types)))
      (:json (json-reader line-reader)))))

(defun decompress-if-needed (stream path)
  (let ((path (file-namestring path)))
   (cond ((str:ends-with? ".log" path :ignore-case t)
          stream)
         ((str:ends-with? ".zst" path :ignore-case t)
          (zstd:make-decompressing-stream stream))
         ((str:ends-with? ".gz" path :ignore-case t)
          (chipz:make-decompressing-stream 'chipz:gzip stream))
         (t (error "Decompression unknown for file type of: ~a" path)))))

;; TODO: In order to go from JSON input to Zeek output, I need to get the
;; FIELD-NAMES for the row with the most JSON keys. You could make the readers
;; return (VALUES ht MORE?) when you have a record and (VALUES FIELD-NAMES NIL)
;; when the file has finished being read.
(defun read-log (path)
  (with-open-file (in path :element-type '(unsigned-byte 8))
    (let* ((stream (decompress-if-needed in path))
           (reader (make-reader stream)))
      (loop for record = (funcall reader)
            while record
            collect record))))
