(in-package :cleek)

(defstruct zeek
  filepath
  path
  stream
  raw-header
  (compression :none :type keyword)     ; :none :gzip :zstd
  line
  types
  fields
  row-strings
  row
  (field->idx (make-hash-table) :type hash-table)
  (field->type (make-hash-table) :type hash-table)
  (status :unparsed :type keyword) ; :unparsed :bytes :? :string-map :parsed-map
  modified?
  (map (make-hash-table) :type hash-table)
  (format :zeek :type keyword)          ; :zeek :json
  accessed-columns
  created-fields
  created-types
  ;; track row num?
  )

(setf *read-default-float-format* 'double-float)

(na:enable-ip-syntax)
(cl-interpol:enable-interpol-syntax)

(declaim (ftype (function (simple-string) double-float) fast-parse-double))
(defun fast-parse-double (string)
  "Parse STRING to double-float. Handles [-]digits[.digits][e|E[-|+]digits].
Avoids the full CL reader overhead of READ-FROM-STRING by doing direct
character-level parsing with rational arithmetic for exact rounding."
  (declare (optimize (speed 3) (safety 0))
           (type simple-string string))
  (let ((len (length string))
        (pos 0)
        (neg nil)
        (significand 0)
        (n-frac 0)
        (exp-part 0)
        (exp-neg nil))
    (declare (fixnum pos len n-frac exp-part))
    ;; Sign
    (when (and (< pos len) (char= (schar string pos) #\-))
      (setf neg t)
      (incf pos))
    ;; Integer part
    (loop while (and (< pos len) (digit-char-p (schar string pos)))
          do (setf significand (+ (* significand 10) (- (char-code (schar string pos)) 48)))
             (incf pos))
    ;; Fractional part — keep accumulating into significand, count digits
    (when (and (< pos len) (char= (schar string pos) #\.))
      (incf pos)
      (loop while (and (< pos len) (digit-char-p (schar string pos)))
            do (setf significand (+ (* significand 10) (- (char-code (schar string pos)) 48)))
               (incf n-frac)
               (incf pos)))
    ;; Exponent
    (when (and (< pos len) (or (char= (schar string pos) #\e) (char= (schar string pos) #\E)))
      (incf pos)
      (when (and (< pos len) (or (char= (schar string pos) #\-) (char= (schar string pos) #\+)))
        (when (char= (schar string pos) #\-)
          (setf exp-neg t))
        (incf pos))
      (loop while (and (< pos len) (digit-char-p (schar string pos)))
            do (setf exp-part (+ (* exp-part 10) (- (char-code (schar string pos)) 48)))
               (incf pos)))
    ;; Combine using rational arithmetic: significand * 10^(exp - n-frac)
    ;; This ensures exact rounding identical to READ-FROM-STRING.
    (let* ((effective-exp (- (if exp-neg (- exp-part) exp-part) n-frac))
           (rational-val (if (>= effective-exp 0)
                             (* significand (expt 10 effective-exp))
                             (/ significand (expt 10 (- effective-exp)))))
           (result (coerce rational-val 'double-float)))
      (if neg (- result) result))))

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

(defun timestamp-to-zeek-ts (ts)
  (+ (local-time:timestamp-to-unix ts)
     (coerce (/ (local-time:nsec-of ts) (expt 10 6)) 'double-float)))

(defun zeek-ts-string-to-timestamp (s)
  (destructuring-bind (secs nsecs) (mapcar #'parse-integer (split-sequence #\. s))
    (local-time:unix-to-timestamp secs :nsec nsecs)))

(defun double-to-timestamp (x)
  (multiple-value-bind (secs nsecs) (truncate x)
    (local-time:unix-to-timestamp secs :nsec (* (expt 10 6) (truncate nsecs)))))

;; type conversions between zeek, JSON, and lisp.
;; Hash table for O(1) type→parser dispatch (replaces alist *zeek-primitive-type-parsers*).
;; Includes both primitive types and compound types (set[...], vector[...]).
;; Compound types are lazily cached on first access.
(defparameter *zeek-type-parsers* (make-hash-table :test 'eq))

(defun %init-zeek-type-parsers ()
  "Populate *zeek-type-parsers* with primitive type parsers."
  (clrhash *zeek-type-parsers*)
  (loop for (type . parser) in
        `((:bool . ,(lambda (x) (if (string= "T" x) t nil)))
          (:count . ,#'parse-integer)
          (:int . ,#'parse-integer)
          (:double . ,#'fast-parse-double)
          (:time . ,#'zeek-ts-string-to-timestamp)
          (:interval . ,#'fast-parse-double)
          (:string . ,#'identity)
          (:port . ,#'parse-integer)
          (:addr . ,#'na:make-ip-address)
          (:subnet . ,#'na:make-ip-network)
          (:enum . ,#'identity))
        do (setf (gethash type *zeek-type-parsers*) parser)))

(%init-zeek-type-parsers)

(defun %get-compound-parser (type)
  "For compound types like :SET[ADDR] or :VECTOR[COUNT], extract the element
type, look up its parser, and return a closure that splits on separator and
maps the element parser. Caches the result in *zeek-type-parsers*."
  (let* ((type-string (keyword->string type)))
    (cl-ppcre:register-groups-bind (nil primitive-type-str)
        ("(set|vector)\\[(.*?)\\]" type-string)
      (let ((element-parser (gethash (string->keyword primitive-type-str) *zeek-type-parsers*)))
        (when element-parser
          (let ((parser (lambda (field)
                          (map 'vector (lambda (f) (funcall element-parser f))
                               (split-sequence *zeek-set-separator* field)))))
            (setf (gethash type *zeek-type-parsers*) parser)
            parser))))))

;; TODO: think about this more. For port, 0 makes sense since it's reserved and should never actually be used. but for
;; something like RCODE, which is a count, 0 is a valid value. I suppose we're typically only doing math on these things
;; and for ORIG_BYTES, 0 as a default makes sense. When would we want to add RCODEs?
(defun zeek-primitive-default (type)
  (case type
    ((:count :int :port) 0)
    ((:double :interval :time) 0.0d0)
    (t 'cl:null)))

(defun %make-type-hash-table (entries)
  "Create eq hash-table from alist entries."
  (let ((ht (make-hash-table :test 'eq)))
    (loop for (type . fn) in entries do (setf (gethash type ht) fn))
    ht))

(defparameter *zeek-jsonify*
  (%make-type-hash-table
   `((:bool . ,(lambda (x) (if x "T" "F")))
     (:time . ,#'timestamp-to-zeek-ts)
     (:addr . ,(lambda (x) (str:downcase (na:str x))))
     (:subnet . ,(lambda (x) (str:downcase (na:str x)))))))

(defparameter *json-zeekify*
  (%make-type-hash-table
   `((:bool . ,(lambda (x) (string= x "T")))
     (:time . ,#'double-to-timestamp)
     (:addr . ,#'na:make-ip-address)
     (:subnet . ,#'na:make-ip-network))))

(defparameter *zeek-stringify*
  (%make-type-hash-table
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
     (:enum . ,#'identity))))

;; TODO: make these learnable, i.e., provide a bunch of zeek logs, output a file of these defparameter calls and load
;; the file if it's present. as long as you fully search the data structure it's fine to have duplicate "keys" in the
;; alist.
(defparameter *path->fields*
  '(
    (:analyzer . (:ts :cause :analyzer_kind :analyzer_name :uid :fuid :id.orig_h :id.orig_p :id.resp_h :id.resp_p :failure_reason :failure_data))
    (:conn . (:ts :uid :id.orig_h :id.orig_p :id.resp_h :id.resp_p :proto :service :duration :orig_bytes :resp_bytes :conn_state :local_orig :local_resp :missed_bytes :history :orig_pkts :orig_ip_bytes :resp_pkts :resp_ip_bytes :tunnel_parents))
    (:dns . (:ts :uid :id.orig_h :id.orig_p :id.resp_h :id.resp_p :proto :trans_id :rtt :query :qclass :qclass_name :qtype :qtype_name :rcode :rcode_name :AA :TC :RD :RA :Z :answers :TTLs :rejected))
    (:files . (:ts :fuid :uid :id.orig_h :id.orig_p :id.resp_h :id.resp_p :source :depth :analyzers :mime_type :filename :duration :local_orig :is_orig :seen_bytes :total_bytes :missing_bytes :overflow_bytes :timedout :parent_fuid :md5 :sha1 :sha256 :extracted :extracted_cutoff :extracted_size))
    (:http . (:ts :uid :id.orig_h :id.orig_p :id.resp_h :id.resp_p :trans_depth :method :host :uri :referrer :version :user_agent :origin :request_body_len :response_body_len :status_code :status_msg :info_code :info_msg :tags :username :password :proxied :orig_fuids :orig_filenames :orig_mime_types :resp_fuids :resp_filenames :resp_mime_types))
    (:packet_filter . (:ts :node :filter :init :success :failure_reason))
    (:quic . (:ts :uid :id.orig_h :id.orig_p :id.resp_h :id.resp_p :version :client_initial_dcid :client_scid :server_scid :server_name :client_protocol :history))
    (:ssh . (:ts :uid :id.orig_h :id.orig_p :id.resp_h :id.resp_p :version :auth_success :auth_attempts :direction :client :server :cipher_alg :mac_alg :compression_alg :kex_alg :host_key_alg :host_key))
    (:ssl . (:ts :uid :id.orig_h :id.orig_p :id.resp_h :id.resp_p :version :cipher :curve :server_name :resumed :last_alert :next_protocol :established :ssl_history :cert_chain_fps :client_cert_chain_fps :sni_matches_cert))
    (:weird . (:ts :uid :id.orig_h :id.orig_p :id.resp_h :id.resp_p :name :addl :notice :peer :source))
    ))

(defparameter *path->types*
  '(
    (:analyzer . (:time :string :string :string :string :string :addr :port :addr :port :string :string))
    (:conn . (:time :string :addr :port :addr :port :enum :string :interval :count :count :string :bool :bool :count :string :count :count :count :count :set[string]))
    (:dns . (:time :string :addr :port :addr :port :enum :count :interval :string :count :string :count :string :count :string :bool :bool :bool :bool :count :vector[string] :vector[interval] :bool))
    (:files . (:time :string :string :addr :port :addr :port :string :count :set[string] :string :string :interval :bool :bool :count :count :count :count :bool :string :string :string :string :string :bool :count))
    (:http . (:time :string :addr :port :addr :port :count :string :string :string :string :string :string :string :count :count :count :string :count :string :set[enum] :string :string :set[string] :vector[string] :vector[string] :vector[string] :vector[string] :vector[string] :vector[string]))
    (:packet_filter . (:time :string :string :bool :bool :string))
    (:quic . (:time :string :addr :port :addr :port :string :string :string :string :string :string :string))
    (:ssh . (:time :string :addr :port :addr :port :count :bool :count :enum :string :string :string :string :string :string :string :string))
    (:ssl . (:time :string :addr :port :addr :port :string :string :string :string :bool :string :string :bool :string :vector[string] :vector[string] :bool))
    (:weird . (:time :string :addr :port :addr :port :string :string :bool :string :string))
  ))

(defparameter *field->type*
  (let ((ht (make-hash-table :test 'eq)))
    (loop for (nil . fields) in *path->fields*
          for (nil . types) in *path->types*
          do (loop for field in fields for type in types
                   do (setf (gethash field ht) type)))
    ht))

(defun infer-log-path-fields-types (zeek-log)
  (unless (zeek-path zeek-log)
    (ensure-map zeek-log)
    (ensure-fields zeek-log)
    ;; LOOP across known fields find first full coverage match, update
    ;; fields and types.
    (loop for (path . fields) in *path->fields*
          for (nil . types) in *path->types*
          unless (set-difference (zeek-fields zeek-log) fields)
            do (setf (zeek-path zeek-log) path
                     (zeek-fields zeek-log) fields
                     (zeek-types zeek-log) types))
    zeek-log))

;; right now you're mostly (only?) using this to handle @@ from zeek logs. so you don't necessarily need to handle this
;; in exactly the same way you handle JSON records. hmm well it would be nice if @@ on both formats worked the same. ugh
;; yeah you need to think about this more. it's fine if @ doesn't work the same, but @@ really should.
;;
;; ordering of filters/mutators matters now. currently, filtering happens after mutation (so you can filter based on a
;; newly created field) but what if we need to filter fields that are going to be fully parsed and used as part of a
;; mutator? hmm. multiple rounds? interleaving sounds annoying though.
(defun parse-zeek-type (field type &optional unset-is-nil?)
  (declare (optimize (speed 3) (debug 0) (space 0) (compilation-speed 0))
           (type string field)
           (type keyword type))
  ;; unset should probably be 'null and empty should probably be #() (since '() is eq to nil)
  (cond ((string= field (string *zeek-unset-field*)) (if unset-is-nil? nil 'cl::null))
        ((string= field (string *zeek-empty-field*))
         (if (eq type :string) "" #()))
        (t (let ((parser (or (gethash type *zeek-type-parsers*)
                             (%get-compound-parser type))))
             (if parser
                 (funcall parser field)
                 (error "Unknown Zeek type: ~a" type))))))

(defun unparse-zeek-type (field type)
  (cond ((eq 'cl:null field) "-")
        ((stringp field)
         field)
        (t (multiple-value-bind (func found) (gethash type *zeek-stringify*)
             (if found
                 (funcall func field)
                 ;; compound type — extract element type once
                 (let ((type-string (keyword->string type)))
                   (cl-ppcre:register-groups-bind (nil primitive-type)
                       ("(set|vector)\\[(.*?)\\]" type-string)
                     (str:join *zeek-set-separator*
                               (map 'list (lambda (f) (unparse-zeek-type f (string->keyword primitive-type)))
                                    field)))))))))

(defun jsonify-zeek-type (field type)
  (cond ((stringp field)
         field)
        (t (multiple-value-bind (func found) (gethash type *zeek-jsonify*)
             (if found
                 (funcall func field)
                 ;; might be compound or just pass-through
                 (let ((type-string (keyword->string type)))
                   (if (or (str:starts-with? "set" type-string)
                           (str:starts-with? "vector" type-string))
                       (cl-ppcre:register-groups-bind (nil primitive-type)
                           ("(set|vector)\\[(.*?)\\]" type-string)
                         (map 'vector (lambda (f) (jsonify-zeek-type f (string->keyword primitive-type)))
                              field))
                       field)))))))

(defun jsonify-zeek-map (zeek-map)
  (loop for field being the hash-key of zeek-map
        do (multiple-value-bind (type found) (gethash field *field->type*)
             (when found
               ;; Zeek format uses "-" to indicate unset while JSON simply has the key not present in the output. We use
               ;; CL:NULL in Zeek formatted logs to differentiate this from the string "-", so we remove these from the
               ;; map when JSONifying a :ZEEK-MAP typed ZEEK-MAP.
               (if (eq 'cl:null (gethash field zeek-map))
                   (remhash field zeek-map)
                   (setf (gethash field zeek-map) (jsonify-zeek-type (gethash field zeek-map) type))))))
  zeek-map)

(defun zeekify-json-type (field type)
  (multiple-value-bind (func found) (gethash type *json-zeekify*)
    (if found
        (funcall func field)
        ;; might be compound or just pass-through
        (let ((type-string (keyword->string type)))
          (if (or (str:starts-with? "set" type-string)
                  (str:starts-with? "vector" type-string))
              (cl-ppcre:register-groups-bind (nil primitive-type)
                  ("(set|vector)\\[(.*?)\\]" type-string)
                (map 'vector (lambda (f) (zeekify-json-type f (string->keyword primitive-type)))
                     field))
              field)))))

(defun zeekify-json-map (json-map)
  (loop for field being the hash-key of json-map
        do (multiple-value-bind (type found) (gethash field *field->type*)
             (when found
               (setf (gethash field json-map) (zeekify-json-type (gethash field json-map) type))))))

(defun stringify-json-type-to-zeek-string (field type)
  (etypecase field
    (simple-vector (if (zerop (length field)) *zeek-empty-field* (format nil "~{~a~^,~}" (coerce field 'list))))
    (boolean (if field "T" "F"))
    (string field)
    (t (if (eq type :time) (format nil "~10,6f" field) (jzon:stringify field)))))
