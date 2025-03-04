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
