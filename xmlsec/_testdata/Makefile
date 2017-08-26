keypair:
	openssl req -x509 \
		-newkey rsa:4096 \
		-keyout test.key.enc \
		-out test.crt \
		-days 3650 \
		-subj "/C=CA/ST=Ontario/L=Toronto/O=Pressly/OU=Org/CN=www.pressly.com" && \
	openssl rsa -in test.key.enc -out test.key
