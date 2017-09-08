# saml

[![Build Status](https://travis-ci.org/goware/saml.svg?branch=master)](https://travis-ci.org/goware/saml)

Package `saml` provides tools and middleware for implementing [SAML based single
sign-on](https://auth0.com/blog/how-saml-authentication-works/).

Currently, the `saml` package depends on the
[xmlsec1](https://www.aleksey.com/xmlsec/index.html) command.

See
[_example/servers](https://github.com/goware/saml/tree/master/_example/servers)
for example implementations of IdP and SP servers.

## SAML SSO basics

![SAML SSO process](https://user-images.githubusercontent.com/385670/30191334-d6ebe85e-9405-11e7-9e61-5d1cd7b47355.png)

### IdP initiated SSO

1. An user selects a service provider (SP) to log in via SSO, a typical use
   case for this is a login button on an intranet.
1. The user is asked by their login details (if not within a session yet).
1. The IdP creates an payload (`AuthnRequest`) containing the user information
   and signs it.
1. The IdP forces the user to submit the signed request to the SP they
   selected. This is typically done via a FORM that is auto-submitted via JavaScript.
1. The SP receives the message and determines if the signature is valid, among
   other details.
1. If the SP decides to trust the message, it can decode the payload with is
   expected to contain user information, such as e-mail address, unique ID and
   name details.
1. The SP uses the payload and provides access to the user.

### SP initiated SSO

1. An user tries to access a restricted URL at a SP.
1. The SP looks up the IdP that matches the private resource and redirects the
   user to a special IdP page. The original URL is passed as a `RelayState`
   parameter.
1. The user is asked by their login details.
1. The IdP creates an payload (`AuthnRequest`) containing the user information
   and signs it.
1. The IdP forces the user to submit the signed request to the SP they
   selected. This is typically done via a FORM that is auto-submitted via JavaScript.
1. The SP receives the message and determines if the signature is valid, among
   other details.
1. If the SP decides to trust the message, it can decode the payload with is
   expected to contain user information, such as e-mail address, unique ID and
   name details.
1. The SP uses the payload, provides access to the user and follows the
   `RelayState` URL.
1. The user gets access to the restricted URL.

## License

Code that is not based on previous Open Source work is released under the MIT
license:

> Copyright (c) 2017 Pressly Inc.
>
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.

Other portions of the code were taken from crewjam's
[saml](https://github.com/crewjam/saml), with the following license:

> Copyright (c) 2015, Ross Kinder
> All rights reserved.
>
> Redistribution and use in source and binary forms, with or without modification,
> are permitted provided that the following conditions are met:
>
> 1. Redistributions of source code must retain the above copyright notice, this
> list of conditions and the following disclaimer.
>
> 2. Redistributions in binary form must reproduce the above copyright notice,
> this list of conditions and the following disclaimer in the documentation
> and/or other materials provided with the distribution.
>
> THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
> ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
> WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
> DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
> FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
> DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
> SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
> CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
> OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
> OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

