DEBUG_FLAGS=
DEBUG_FLAGS="${DEBUG_FLAGS} -debug"
DEBUG_FLAGS="${DEBUG_FLAGS} -state"
DEBUG_FLAGS="${DEBUG_FLAGS} -msg"
DEBUG_FLAGS="${DEBUG_FLAGS} -tlsextdebug"

CIPHERS=
CIPHERS="${CIPHERS}:ECDHE-ECDSA-AES256-SHA"
CIPHERS="${CIPHERS}:ECDHE-ECDSA-AES128-GCM-SHA256"

openssl s_server \
	-dtls1_2 \
	-cert cert.pem \
	-key key.pem \
	-accept 4444 \
	${DEBUG_FLAGS} \
	-cipher ${CIPHERS}
