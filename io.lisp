(in-package :cleek)

(defvar *input-format* :zeek) ; or :json
(defvar *output-format* :zeek) ; or :json

(defvar *input-compression* :txt) ; or :zstd or :gzip
(defvar *output-compression* :txt) ; or :zstd or :gzip

(defvar *zeek-field-separator* #\Tab)
(defvar *zeek-set-separator* #\,)
(defvar *zeek-unset-field #\-)
(defvar *zeek-open-close-time-format* '(:year "-" (:month 2) "-" (:day 2) "-" (:hour12 2) "-" (:min 2) "-" (:sec 2))
  "Time format for #open and #close sections of Zeek format header and footer.")

(defparameter *buffer-size* (expt 2 9)) ; you'll want to bump this. also prob be vars
(defparameter *buffer* (make-array *buffer-size* :element-type '(unsigned-byte 8)))
(defvar *newline-byte* (char-code #\Newline))

(defun ->keyword (s) (ax:make-keyword (str:upcase s)))

(defun timestamp-to-zeek-open-close-string (ts)
  (local-time:format-timestring nil ts :format *zeek-open-close-time-format* :timezone local-time:+utc-zone+))

(defun timestamp-to-zeek-ts-string (ts)
  (format nil "~d.~6,'0d" (local-time:timestamp-to-unix ts) (local-time:nsec-of ts)))

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

(defvar *field-names* nil)

(defun generate-zeek-header (field-names)
  (let ((field-names (mapcar #'str:downcase (mapcar #'string field-names))))
   (format nil "~a~%~a~%~a~%~a~%~a~%~a~%~a~%~a~%"
           (format nil "#separator \\x~2,'0x" (char-code *zeek-field-separator*))
           (format nil (format nil "#set_separator~a~~a" *zeek-field-separator*) *zeek-set-separator*)
           (format nil (format nil "#empty_field~a~~a" *zeek-field-separator*) "(empty)")
           (format nil (format nil "#unset_field~a~~a" *zeek-field-separator*) "-")
           (format nil (format nil "#path~a~~a" *zeek-field-separator*) "cleek_path") ; TODO
           (format nil (format nil "#open~a~~a" *zeek-field-separator*) (timestamp-to-zeek-open-close-string (local-time:now)))
           (format nil (format nil "#fields~a~~a" *zeek-field-separator*) (str:join *zeek-field-separator* field-names))
           (format nil (format nil "#types~a~~a" *zeek-field-separator*) (str:join *zeek-field-separator* (make-list (length field-names) :initial-element "string")))))) ; TODO

(defun read-zeek-header (line-reader)
  (let ((types nil)
        (more-header? t))
    (loop while more-header?
          for line = (funcall line-reader)
          when (str:starts-with? "#fields" line)
            do (setf *field-names* (mapcar #'->keyword (rest (str:split *zeek-field-separator* line))))
          when (str:starts-with? "#types" line)
            do (setf types (mapcar #'->keyword (rest (str:split *zeek-field-separator* line)))
                     more-header? nil))
    (values *field-names* types)))

(defun zeek-reader (line-reader)
  (read-zeek-header line-reader)
  (let ((num-fields (length *field-names*)))
    (lambda ()
      (let ((line (funcall line-reader))
            (ht (make-hash-table :size num-fields)))
        (unless (or (not line)
                    (char= #\# (char line 0)))
          (loop for field in (str:split *zeek-field-separator* line)
                for name in *field-names*
                do (setf (gethash name ht) field)))
        (unless (zerop (hash-table-count ht))
          ht)))))

(defun json-reader (line-reader)
  (let ((num-fields 0))
    (lambda ()
      (ax:when-let* ((line (funcall line-reader))
                     (json (jzon:parse line :key-fn #'->keyword)))
        (when (> (hash-table-count json) num-fields)
          (setf *field-names* (ax:hash-table-keys json))
          (setf num-fields (length *field-names*)))
        json))))

(defun make-reader (stream)
  (multiple-value-bind (line-reader format) (sequence-line-reader stream)
    (ecase format
      (:zeek (zeek-reader line-reader))
      (:json (json-reader line-reader)))))

(defun json-writer (stream field-names)
  (lambda (record)
    (write-sequence (record->bytes record field-names :json) stream)))

(defun zeek-writer (stream field-names)
  (write-sequence (babel:string-to-octets (generate-zeek-header field-names)) stream)
  (values (lambda (record)
            (write-sequence (record->bytes record field-names :zeek) stream))
          (lambda () (write-sequence
                 (babel:string-to-octets
                  (format nil (format nil "#close~a~~a~%" *zeek-field-separator*)
                          (timestamp-to-zeek-open-close-string (local-time:now))))
                 stream))))

(defun make-writer (stream field-names format)
  (ecase format
    (:zeek (zeek-writer stream field-names))
    (:json (json-writer stream field-names))))

(defun get-de/compression-func (filename compress?)
  (if compress?
      (cond ((str:ends-with? ".log" filename :ignore-case t)
             nil)
            ((str:ends-with? ".zst" filename :ignore-case t)
             (lambda (stream) (zstd:make-compressing-stream stream)))
            ((str:ends-with? ".gz" filename :ignore-case t)
             (lambda (stream) (salza2:make-compressing-stream 'salza2:gzip-compressor stream)))
            (t (error "No compression implemented for file type: ~a" filename)))
      (cond ((str:ends-with? ".log" filename :ignore-case t)
             nil)
            ((str:ends-with? ".zst" filename :ignore-case t)
             (lambda (stream) (zstd:make-decompressing-stream stream)))
            ((str:ends-with? ".gz" filename :ignore-case t)
             (lambda (stream) (chipz:make-decompressing-stream 'chipz:gzip stream)))
            (t (error "No decompression implemented for file type: ~a" filename)))))

(defmacro with-open-log ((stream filespec &rest options) &body body)
  (ax:with-gensyms (io de/compressor)
    `(let ((,de/compressor (get-de/compression-func (file-namestring ,filespec)
                                                    ,(find :output options))))
       (if ,de/compressor
           (with-open-file (,io ,filespec :element-type '(unsigned-byte 8) ,@options)
              (with-open-stream (,stream (funcall ,de/compressor ,io))
                ,@body))
           (with-open-file (,stream ,filespec :element-type '(unsigned-byte 8) ,@options)
              ,@body)))))

(defun read-log (path)
  (let (*field-names*)
    (with-open-log (stream path)
      (let ((reader (make-reader stream)))
        (values (loop for record = (funcall reader)
                      while record
                      collect record)
                *field-names*)))))

(defun record->bytes (record field-names output-format)
  (case output-format
    (:json (babel:string-to-octets (format nil "~a~%" (jzon:stringify record))))
    (:zeek ;; this is incomplete until you handle JSON arrays (when going from json->zeek).
     (babel:string-to-octets
      (format nil (format nil "~~{~~a~~^~C~~}~~%" *zeek-field-separator*)
              (loop for field-name in field-names
                    collect (gethash field-name record "-")))))))

(defun write-log (records field-names output-format path)
  (with-open-log (stream path :direction :output :if-exists :supersede)
   (when (eq output-format :zeek)
     (write-sequence (babel:string-to-octets (generate-zeek-header field-names)) stream))
    (loop for record in records
          do (write-sequence (record->bytes record field-names output-format)
                             stream))
    (when (eq output-format :zeek)
      (write-sequence
       (babel:string-to-octets
        (format nil (format nil "#close~a~~a~%" *zeek-field-separator*)
                (timestamp-to-zeek-open-close-string (local-time:now))))
       stream))))

(defun rw-test ()
  (multiple-value-bind (records field-names) (read-log #P"/Users/yacin/code/cleek/data/json/zstd/conn.log.zst")
    (write-log records field-names :zeek #P"/Users/yacin/tmp/out/conn.zeek.log"))
  (multiple-value-bind (records field-names) (read-log #P"/Users/yacin/code/cleek/data/json/zstd/conn.log.zst")
    (write-log records field-names :zeek #P"/Users/yacin/tmp/out/conn.zeek.log.zst"))
  (multiple-value-bind (records field-names) (read-log #P"/Users/yacin/code/cleek/data/json/zstd/conn.log.zst")
    (write-log records field-names :zeek #P"/Users/yacin/tmp/out/conn.zeek.log.gz"))
  (multiple-value-bind (records field-names) (read-log #P"/Users/yacin/code/cleek/data/json/zstd/conn.log.zst")
    (write-log records field-names :json #P"/Users/yacin/tmp/out/conn.json.log"))
  (multiple-value-bind (records field-names) (read-log #P"/Users/yacin/code/cleek/data/json/zstd/conn.log.zst")
    (write-log records field-names :json #P"/Users/yacin/tmp/out/conn.json.log.zst"))
  (multiple-value-bind (records field-names) (read-log #P"/Users/yacin/code/cleek/data/json/zstd/conn.log.zst")
    (write-log records field-names :json #P"/Users/yacin/tmp/out/conn.json.log.gz")))
