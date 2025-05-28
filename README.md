# `cleek`

`cleek` is a command line tool for working with Zeek logs. It provides a Lispy
DSL for filtering and mutating Zeek logs in either TSV or JSON formats, and
allows converting between the two. It's primary use-case is quick'n'dirty
processing or data analysis of Zeek logs where you may not have the logs already
stored in a database or SIEM for easier access.

## Usage

```
¡ cleek --help
NAME:
  cleek - Concatenate, filter, and convert Zeek logs

USAGE:
  cleek [ZEEK-LOG]...

OPTIONS:
      --help                      display usage information and exit
      --version                   display version and exit
  -d, --debug-compiled-functions  Debug compiled functions
  -f, --output-format <CHOICE>    Output format [default: input-format] [choices: zeek, json,
                                  input-format]
  -m, --mutator <VALUE>           Mutator expression
  -o, --output-file <VALUE>       Output file [default: /dev/stdout]
  -x, --filter <VALUE>            Filter expression
```

`cleek` reads plain text Zeek logs from a file (or `STDIN`) and writes them back
to `STDOUT`. If no filters or mutators are provided, `cleek` behaves like a Zeek
log aware version of `cat`:

```
~/code/cleek topic/yacin/modified-and-fmt-change*
¡ cat data/test-input/zeek/ssh.log 
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	ssh
#open	2025-04-01-09-50-28
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	version	auth_success	auth_attempts	direction	client	server	cipher_alg	mac_alg	compression_alg	kex_alg	host_key_alg	host_key
#types	time	string	addr	port	addr	port	count	bool	count	enum	string	string	string	string	string	string	string	string
1623187704.078114	C4KEFY1wBmfzxmr0T9	140.249.20.119	48610	192.168.1.145	22	2	-	0	INBOUND	SSH-2.0-libssh-0.6.3	SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2	aes256-ctr	hmac-sha1	none	curve25519-sha256@libssh.org	ecdsa-sha2-nistp256	a5:1b:06:f3:65:01:e1:a6:4d:86:a4:d6:49:cd:50:f3
1623187704.078275	ClzWtFaN2gWsP5wNb	140.249.20.119	48610	71.127.52.28	22	2	-	0	-	SSH-2.0-libssh-0.6.3	SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2	aes256-ctr	hmac-sha1	none	curve25519-sha256@libssh.org	ecdsa-sha2-nistp256	a5:1b:06:f3:65:01:e1:a6:4d:86:a4:d6:49:cd:50:f3
#close	2025-04-01-09-50-28

~/code/cleek topic/yacin/modified-and-fmt-change*
¡ cat data/test-input/zeek/ssh.log data/test-input/zeek/ssh.log | cleek
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	ssh
#open	2025-04-01-09-50-28
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	version	auth_success	auth_attempts	direction	client	server	cipher_alg	mac_alg	compression_alg	kex_alg	host_key_alg	host_key
#types	time	string	addr	port	addr	port	count	bool	count	enum	string	string	string	string	string	string	string	string
1623187704.078114	C4KEFY1wBmfzxmr0T9	140.249.20.119	48610	192.168.1.145	22	2	-	0	INBOUND	SSH-2.0-libssh-0.6.3	SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2	aes256-ctr	hmac-sha1	none	curve25519-sha256@libssh.org	ecdsa-sha2-nistp256	a5:1b:06:f3:65:01:e1:a6:4d:86:a4:d6:49:cd:50:f3
1623187704.078275	ClzWtFaN2gWsP5wNb	140.249.20.119	48610	71.127.52.28	22	2	-	0	-	SSH-2.0-libssh-0.6.3	SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2	aes256-ctr	hmac-sha1	none	curve25519-sha256@libssh.org	ecdsa-sha2-nistp256	a5:1b:06:f3:65:01:e1:a6:4d:86:a4:d6:49:cd:50:f3
1623187704.078114	C4KEFY1wBmfzxmr0T9	140.249.20.119	48610	192.168.1.145	22	2	-	0	INBOUND	SSH-2.0-libssh-0.6.3	SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2	aes256-ctr	hmac-sha1	none	curve25519-sha256@libssh.org	ecdsa-sha2-nistp256	a5:1b:06:f3:65:01:e1:a6:4d:86:a4:d6:49:cd:50:f3
1623187704.078275	ClzWtFaN2gWsP5wNb	140.249.20.119	48610	71.127.52.28	22	2	-	0	-	SSH-2.0-libssh-0.6.3	SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2	aes256-ctr	hmac-sha1	none	curve25519-sha256@libssh.org	ecdsa-sha2-nistp256	a5:1b:06:f3:65:01:e1:a6:4d:86:a4:d6:49:cd:50:f3
#close	2025-05-11-08-10-00
```

`cleek` becomes more interesting when _filters_, specified with `-x`, and
_mutators_, `-m`, are provided. A filter argument is a Lisp form that is
evaluated against each line of a Zeek log. If it returns a "truthy" value, the
line is printed, otherwise it is suppressed. A mutator is an implicit PROGN of
Lisp forms that add or modify columns. Mutators are run before filters. Both
require references to columns from the data to be meaningful, which are denoted
by `@colname` or `@@colname`, or references to the whole line represented by the
special symbol `LINE`.

### Filters

The most common function to use with `LINE` is `~`, which is a regular
expression search. `~` takes two arguments: a string or regular expression, and
`LINE` or the column you're matching against.

```
~/code/cleek topic/yacin/modified-and-fmt-change*
¡ cat data/test-input/zeek/ssh.log | cleek -x '(~ "INBOUND" LINE)'
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	ssh
#open	2025-04-01-09-50-28
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	version	auth_success	auth_attempts	direction	client	server	cipher_alg	mac_alg	compression_alg	kex_alg	host_key_alg	host_key
#types	time	string	addr	port	addr	port	count	bool	count	enum	string	string	string	string	string	string	string	string
1623187704.078114	C4KEFY1wBmfzxmr0T9	140.249.20.119	48610	192.168.1.145	22	2	-	0	INBOUND	SSH-2.0-libssh-0.6.3	SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2	aes256-ctr	hmac-sha1	none	curve25519-sha256@libssh.org	ecdsa-sha2-nistp256	a5:1b:06:f3:65:01:e1:a6:4d:86:a4:d6:49:cd:50:f3
#close	2025-05-11-08-35-36
```

When using regular expressions, it's recommended to use the
[cl-interpol](http://edicl.github.io/cl-interpol/#syntax) syntax to save on
backslashes. The following two filters are equvalent:

```
~/code/cleek topic/yacin/modified-and-fmt-change*
¡ cat data/test-input/zeek/ssh.log | cleek -x '(~ #?/140\..*?\s+\d+\s+71\.127/ LINE)'
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	ssh
#open	2025-04-01-09-50-28
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	version	auth_success	auth_attempts	direction	client	server	cipher_alg	mac_alg	compression_alg	kex_alg	host_key_alg	host_key
#types	time	string	addr	port	addr	port	count	bool	count	enum	string	string	string	string	string	string	string	string
1623187704.078275	ClzWtFaN2gWsP5wNb	140.249.20.119	48610	71.127.52.28	22	2	-	0	-	SSH-2.0-libssh-0.6.3	SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2	aes256-ctr	hmac-sha1	none	curve25519-sha256@libssh.org	ecdsa-sha2-nistp256	a5:1b:06:f3:65:01:e1:a6:4d:86:a4:d6:49:cd:50:f3
#close	2025-05-11-08-39-49

~/code/cleek topic/yacin/modified-and-fmt-change*
¡ cat data/test-input/zeek/ssh.log | cleek -x '(~ "140\\..*?\\s+\\d+\\s+71\\.127" LINE)'
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	ssh
#open	2025-04-01-09-50-28
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	version	auth_success	auth_attempts	direction	client	server	cipher_alg	mac_alg	compression_alg	kex_alg	host_key_alg	host_key
#types	time	string	addr	port	addr	port	count	bool	count	enum	string	string	string	string	string	string	string	string
1623187704.078275	ClzWtFaN2gWsP5wNb	140.249.20.119	48610	71.127.52.28	22	2	-	0	-	SSH-2.0-libssh-0.6.3	SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2	aes256-ctr	hmac-sha1	none	curve25519-sha256@libssh.org	ecdsa-sha2-nistp256	a5:1b:06:f3:65:01:e1:a6:4d:86:a4:d6:49:cd:50:f3
#close	2025-05-11-08-40-11
```

If you find yourself using `LINE` a lot, you may want to just use `grep`.
Accessing columns directly is by far more common. `@colname` does an initial
parse of the data: to a `string` for TSVs and to a JSON datatype for JSON (see
[JZON](https://github.com/Zulu-Inuoe/jzon) documentation for details).
`@@colname` fully parses the column to a useful representation based on the Zeek
data type:

* `bool` -> `(or t nil)`
* `count` -> `integer`
* `int` -> `integer`
* `time` -> `local-time:timestamp`
* `interval` -> `double-float`
* `string` -> `string`
* `port` -> `integer`
* `addr` -> `netaddr::ip-address`
* `subnet` -> `netaddr::ip-network`
* `enum` -> `string`

Oftentimes when working with Zeek TSVs you can get by with just strings:

```
~/code/cleek topic/yacin/modified-and-fmt-change*
¡ cat data/test-input/zeek/ssh.log | cleek -x '(str:starts-with? "C4" @uid)' # alternatively: cleek -x '(~ #?/^C4/ @uid)'
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	ssh
#open	2025-04-01-09-50-28
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	version	auth_success	auth_attempts	direction	client	server	cipher_alg	mac_alg	compression_alg	kex_alg	host_key_alg	host_key
#types	time	string	addr	port	addr	port	count	bool	count	enum	string	string	string	string	string	string	string	string
1623187704.078114	C4KEFY1wBmfzxmr0T9	140.249.20.119	48610	192.168.1.145	22	2	-	0	INBOUND	SSH-2.0-libssh-0.6.3	SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2	aes256-ctr	hmac-sha1	none	curve25519-sha256@libssh.org	ecdsa-sha2-nistp256	a5:1b:06:f3:65:01:e1:a6:4d:86:a4:d6:49:cd:50:f3
#close	2025-05-11-08-43-11
```

Logical operators will function as expected. Ensure that the filter is just a
single expression!

```
~/code/cleek topic/yacin/modified-and-fmt-change*
¡ cat data/test-input/zeek/dns.log | cleek -x '(and (string= "A" @qtype_name) (string= "NXDOMAIN" @rcode_name))'
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	dns
#open	2025-04-01-09-50-28
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	trans_id	rtt	query	qclass	qclass_name	qtype	qtype_name	rcode	rcode_name	AA	TC	RD	RA	Z	answers	TTLs	rejected
#types	time	string	addr	port	addr	port	enum	count	interval	string	count	string	count	string	count	string	bool	bool	bool	bool	count	vector[string]	vector[interval]	bool
1623187699.490760	CYfPGx7uiiW6Cz4dk	71.127.52.28	50977	8.8.8.8	53	udp	6226	-	netmon-control.dropbox.com	1	C_INTERNET	1	A	3	NXDOMAIN	F	F	T	F	0	--	F
1623187699.490583	CiZcmz1j6KBBxTwLCa	192.168.1.77	50977	8.8.8.8	53	udp	6226	-	netmon-control.dropbox.com	1	C_INTERNET	1	A	3	NXDOMAIN	F	F	T	F	0	--	F
#close	2025-05-11-08-49-37
```

If we use `@@`, we can do numerical comparisons or even check that the field is set:

```
~/code/cleek topic/yacin/modified-and-fmt-change*
¡ cat data/test-input/zeek/dns.log | cleek -x '(and (> @@id.resp_p 53) (zerop @@trans_id) @@rcode_name)'
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	dns
#open	2025-04-01-09-50-28
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	trans_id	rtt	query	qclass	qclass_name	qtype	qtype_name	rcode	rcode_name	AA	TC	RD	RA	Z	answers	TTLs	rejected
#types	time	string	addr	port	addr	port	enum	count	interval	string	count	string	count	string	count	string	bool	bool	bool	bool	count	vector[string]	vector[interval]	bool
1623187708.119731	ClA7M216ae3KJyG7T3	192.168.1.39	5353	224.0.0.251	5353	udp	0	-	_spotify-connect._tcp.local	-	-	-	-	0	NOERROR	T	F	F	F	0	ee1519d9-ae41-5824-879e-cc14e60-0._spotify-connect._tcp.local,_spotify-connect._tcp.local	60.000000,60.000000	F
1623187709.131610	ClA7M216ae3KJyG7T3	192.168.1.39	5353	224.0.0.251	5353	udp	0	-	_spotify-connect._tcp.local	-	-	-	-	0	NOERROR	T	F	F	F	0	ee1519d9-ae41-5824-879e-cc14e60-0._spotify-connect._tcp.local,_spotify-connect._tcp.local	60.000000,60.000000	F
#close	2025-05-11-09-00-56
```

### Mutators

Mutators can add or mutate existing fields programmatically. For example, we can
swap the `id.orig_h` and `id.resp_h` fields:

```
~/code/cleek topic/yacin/modified-and-fmt-change*
¡ cat data/test-input/zeek/dns.log | cleek -m '(psetf @id.orig_h @id.resp_h @id.resp_h @id.orig_h)' -x '(string/= @id.orig_h "8.8.8.8")'
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	dns
#open	2025-04-01-09-50-28
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	trans_id	rtt	query	qclass	qclass_name	qtype	qtype_name	rcode	rcode_name	AA	TC	RD	RA	Z	answers	TTLs	rejected
#types	time	string	addr	port	addr	port	enum	count	interval	string	count	string	count	string	count	string	bool	bool	bool	bool	count	vector[string]	vector[interval]	bool
1623187693.607810	CanCs12tqZRLxCYjIg	8.8.4.4	37086	71.127.52.28	53	udp	57211	-	connectivity-check.ubuntu.com	1	C_INTERNET	28	AAAA	0	NOERROR	F	F	T	F	0	-	-F
1623187693.607462	COwkyTZyVphR1U9J5	8.8.4.4	37086	192.168.1.145	53	udp	57211	-	connectivity-check.ubuntu.com	1	C_INTERNET	28	AAAA	0	NOERROR	F	F	T	F	0	-	-F
1623187693.612375	CP62ty2zbRELFEA7Xc	8.8.4.4	42781	71.127.52.28	53	udp	59274	-	connectivity-check.ubuntu.com	1	C_INTERNET	28	AAAA	0	NOERROR	F	F	T	F	0	-	-F
1623187693.612199	C3blIs2Cic3aoqkxyg	8.8.4.4	42781	192.168.1.145	53	udp	59274	-	connectivity-check.ubuntu.com	1	C_INTERNET	28	AAAA	0	NOERROR	F	F	T	F	0	-	-F
1623187712.460603	CaI9sb3NP4gVqBfdC7	71.252.0.12	45755	71.127.52.28	53	udp	6316	0.001585	dynamicdns.park-your-domain.com	1	C_INTERNET	1	A	0	NOERROR	F	F	T	T	0104.219.249.157	402.000000	F
1623187708.119731	ClA7M216ae3KJyG7T3	224.0.0.251	5353	192.168.1.39	5353	udp	0	-	_spotify-connect._tcp.local	-	-	-	-	0	NOERROR	T	F	F	F	0	ee1519d9-ae41-5824-879e-cc14e60-0._spotify-connect._tcp.local,_spotify-connect._tcp.local	60.000000,60.000000	F
1623187709.131610	ClA7M216ae3KJyG7T3	224.0.0.251	5353	192.168.1.39	5353	udp	0	-	_spotify-connect._tcp.local	-	-	-	-	0	NOERROR	T	F	F	F	0	ee1519d9-ae41-5824-879e-cc14e60-0._spotify-connect._tcp.local,_spotify-connect._tcp.local	60.000000,60.000000	F
1623187719.304016	Cq23XQ1M0xQe1XsU01	224.0.0.251	5353	192.168.1.77	5353	udp	0	-	_rfb._tcp.local	1	C_INTERNET	12	PTR	-	-	F	F	F	F	0	-	-	F
1623187719.304136	CgbKYo4zyTSWZMRi6c	ff02::fb	5353	fe80::1462:3ff9:fd68:b0fc	5353	udp	0	-	_rfb._tcp.local	1	C_INTERNET	12	PTR	-	-	F	F	F	F	0	--	F
1623187719.310901	CefLlJ3hXT0Ej5uhJj	224.0.0.251	5353	192.168.1.199	5353	udp	0	-	_rfb._tcp.local	1	C_INTERNET	12	PTR	-	-	F	F	F	F	0	-	-	F
1623187719.312043	C0Nrcq1vlkZd3pJYY3	ff02::fb	5353	fe80::c9f:10f3:3b0a:b833	5353	udp	0	-	_rfb._tcp.local	1	C_INTERNET	12	PTR	-	-	F	F	F	F	0	--	F
#close	2025-05-11-09-16-05
```

Or add a field, `@tld`, but grabbing the last part from `@query`:

```
~/code/cleek topic/yacin/modified-and-fmt-change*
¡ cat data/test-input/zeek/dns.log | cleek -m '(setf @tld (first (last (str:split "." @query))))' | zeek-cut query tld | head
connectivity-check.ubuntu.com	com
connectivity-check.ubuntu.com	com
connectivity-check.ubuntu.com	com
connectivity-check.ubuntu.com	com
unchartedsoftware.slack.com	com
unchartedsoftware.slack.com	com
edgeapi.slack.com	com
edgeapi.slack.com	com
d.dropbox.com	com
d.dropbox.com	com
```

See [tests.lisp](./tests.lisp) for more usage examples.

### Helpers

`cleek` has a handful of helper functions. See [their documentation](https://yacin.nadji.us/cleek/index.html#PACKAGE%20CLEEK) for
usage. Any unary function defined here can be suffixed with `!` to replace the
colulmn with the result of applying the function to the column's value. Even
though the function is unary, with the `!` suffix it can take an arbitrary
number of columns. The transformation is essentially:

```
(anonip! @c1 @c2 @c3)
;; becomes
(setf @c1 (anonip @c1)
      @c2 (anonip @c2)
      @c3 (anonip @c3))
```

### Common Filters and Mutators

The file [common-filters-and-mutators.lisp](./common-filters-and-mutators.lisp)
can be augmented with additional filters or mutators you would like to use at
runtime. If the modified file is present and located in
`~/.config/cleek/common-filters-and-mutators.lisp` the file is read/compiled
when `cleek` is run and those are available to use as filters or mutators. If
you find yourself re-using a large filter or mutator often, it would make sense
to add it here. Note that untrusted code should _not_ end up here or you're
going to have a bad time.

## Building

`cleek` depends on `("str" "uiop" "alexandria" "cl-ppcre" "cl-tld" "netaddr"
"cl-dns" "com.inuoe.jzon" "local-time" "clingon" "serapeum" "split-sequence"
"cl-interpol" "ironclad")` to build, all of which are on quicklisp save
[cl-dns](https://github.com/ynadji/cl-dns) and
[netaddr](https://github.com/ynadji/netaddr). If you currently use [roswell](#)
you can build with `make`. Otherwise, use `$ lisp-impl --eval "(progn (asdf:make
:cleek) (quit))"` or the equivalent. `cleek` has only been tested with SBCL on
ARM macOS and amd64 Linux.
