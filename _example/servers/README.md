# IdP and SP servers

The `saml` package includes two servers that can be used as minimal examples
for building SP and IdP servers that can follow the IdP-initiated and
SP-initiated sequences.

In order to use these servers you'll need a certificate and a passwordless
private key. You can generate the proper keys with `openssl`:

Generate SP key
```
openssl req -x509 \
  -nodes \
  -newkey rsa:4096 \
  -keyout sp.key.enc \
  -out sp.crt \
  -days 3650 \
  -subj "/C=CA/ST=Ontario/L=Toronto/O=Pressly/OU=Org/CN=www.pressly.com"

openssl rsa -in sp.key.enc -out sp.key
```

Generate IdP key
```
openssl req -x509 \
  -nodes \
  -newkey rsa:4096 \
  -keyout idp.key.enc \
  -out idp.crt \
  -days 3650 \
  -subj "/C=CA/ST=Ontario/L=Toronto/O=Pressly/OU=Org/CN=www.pressly.com"

openssl rsa -in idp.key.enc -out idp.key
```

You'll need two keypairs, one for the SP and the other for the IdP.

Don't use the above command for creating keypairs for production use, this is
only for testing.

Once you have both keypairs install the `idp-server` tool:

```
go install github.com/pressly/saml/_example/servers/idp-server
```

and the `sp-server` tool:

```
go install github.com/pressly/saml/_example/servers/sp-server
```

## Testing IdP-initiated SSO

The [IdP-initiated
SSO](http://saml.xml.org/wiki/idp-initiated-single-sign-on-post-binding) is a
SSO sequence that begins with the identity provider sending an unsolicited
request to a service provider.

In order to simulate said sequence, run the `idp-server` and `sp-server`
commands like this:

```
idp-server \
  -listen-addr 127.0.0.1:1117 \
  -public-url http://127.0.0.1:1117 \
  -pubkey-cert-pem ./idp.crt \
  -privkey-pem ./idp.key \
  -sp-metadata-url http://127.0.0.1:1113/metadata.xml \
  -initiated-by idp
```

```
sp-server \
  -listen-addr 127.0.0.1:1113 \
  -public-url http://127.0.0.1:1113 \
  -pubkey-cert-pem ./sp.crt \
  -privkey-pem ./sp.key \
  -idp-metadata-url http://127.0.0.1:1117/metadata.xml \
  -initiated-by idp
```

Then go to the IdP server's public address to begin the login process.

The test user credentials are:
* username: anakin
* password: skywalker

## SP-initiated SSP

The [SP-initiated
SSO](http://saml.xml.org/wiki/sp-initiated-single-sign-on-postartifact-bindings)
is a SSO sequence where the service provider redirects the user to the identity
provider to log in.

In order to simulate said sequence, run the `idp-server` and `sp-server`
commands like this:

```
idp-server \
  -listen-addr 127.0.0.1:1117 \
  -public-url http://127.0.0.1:1117 \
  -pubkey-cert-pem ./idp.crt \
  -privkey-pem ./idp.key \
  -sp-metadata-url http://127.0.0.1:1113/metadata.xml \
  -initiated-by sp
```

```
sp-server \
  -listen-addr 127.0.0.1:1113 \
  -public-url http://127.0.0.1:1113 \
  -pubkey-cert-pem ./sp.crt \
  -privkey-pem ./sp.key \
  -idp-metadata-url http://127.0.0.1:1117/metadata.xml \
  -initiated-by sp
```

Then go to the SP server's public address to begin the login process.
