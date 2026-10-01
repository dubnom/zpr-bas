# bas - Basic Authentication Service

Provides a ZPR authentication service that uses RSA keypairs to confirm
actor identity.  Can be configured to return atbitrary attributes along
with an identity token.

This creates a simple file based database on disk.

To run the server you need to create a certificate for TLS.  Eg,

```bash
openssl req -new -newkey rsa:4096 -x509 -sha256 -days 365 -nodes -out tlscert.crt -keyout tlskey.key
```

The Visa Service verifies BAS access tokens with a shared HMAC-SHA384 key. Generate
one from a cryptographically secure random source and restrict it to the BAS and
Visa Service accounts (mode `0600`):

```bash
openssl rand -out bas-token-hmac.key 48
chmod 600 bas-token-hmac.key
```

Configure the Visa Service's matching
`[trusted_service_http.bas].token_verification_key_file` to this same secret.
The current `zpr-oauthrsa` flow proves possession of an adapter CN's RSA key and
returns its mapped claims; it is not an interactive human login or session UI.


## Demonstration Usage

Add a "record" to the database.  Here we add an actor with CN=`mk.zpr`.

    ./bas create mk.zpr



Add some attributes. Here we add a single value attribute "color", a tag attribute "manager", and a multi
value attribute "groups".

    ./bas add-attribute mk.zpr color:green manager groups:marketing,finance

Start the server

    ./bas serve --key certs/tlskey.key --cert certs/tlscert.crt --token-key-file certs/bas-token-hmac.key


Kick of authentication/authorization.  Now we are acting like an adapter.  This step will return a challange nonce
that the adapter is supposed to use to generate a signed payload.

    curl -ik -H "Content-Type: application/x-www-form-urlencoded" https://localhost:4000/preauthorize\?response_type\=code\&client_id\=mk.zpr

Response:

```bash
HTTP/1.1 200 OK
content-type: application/json
content-length: 100
date: Thu, 17 Apr 2025 15:30:11 GMT

{"nonce":"lta7gNo3sfCwvJaazs2r9+4F6FNCt0BcYMhGaVndLQn+3cMdGCdT/qo5FTZErfnwAc+leub2qfKPZQ0qDIi8xg=="}
```

When a client adapter gets this message, it will use the nonce to create a `payload` to send
back in order to verify that the adapter holds the correct private key.  The payload is just
the RSA signature (sha256, PKCS1) of the nonce.

In the call below the payload is set to `fake`.  If you want the example to work you need to
compute a real payload as described.  The `Response` below is an example of a successful
response which you definately will not get if you pass `fake` for your payload value.

    curl -d '{"client_id":"mk.zpr","nonce":"lta7gNo3sfCwvJaazs2r9+4F6FNCt0BcYMhGaVndLQn+3cMdGCdT/qo5FTZErfnwAc+leub2qfKPZQ0qDIi8xg==","payload":"fake"}' \
      -ik -H "Content-Type: application/json" \
      -X POST https://localhost:4000/authorize

Response:

```bash
HTTP/1.1 302 Found
location: https://auth.zpr?code=12625318488887027953106631712105642125
content-length: 0
date: Thu, 17 Apr 2025 15:31:05 GMT
```

Normally the adapter would now create the "BLOB" (including the `code` returned above) and
send it to the visa service for processing.  The visa service then calls the `/token`
endpoint to get the authorization token (a JWT token).

So here we act like the visa service:


    curl -ik -d "grant_type=authorization_code&code=12625318488887027953106631712105642125&client_id=mk.zpr&redirect_url=ha" \
      -X POST https://localhost:3999/token

Response:

```bash
HTTP/1.1 200 OK
content-type: application/json
content-length: 403
date: Thu, 17 Apr 2025 15:34:17 GMT

{"access_token":"eyJhbGciOiJIUzM4NCJ9.eyJhdWQiOiJ6cHIiLCJleHAiOiIxNzQ0OTkwMjY1IiwiaWF0IjoiMTc0NDkwMzg2NSIsImlzcyI6Inpwci9iYXMiLCJzdWIiOiJtay56cHIiLCJ6cHJhL2NvbG9yIjoiZ3JlZW4iLCJ6cHJhL2dyb3VwcyI6Im1hcmtldGluZyxmaW5hbmNlIiwienByYS9tYW5hZ2VyIjoiIn0.jiKfmi_aQdfb-y5WiJL27fOzViHPOef0pLzGtWXyGs8UN0l4jR9kYULYQCPHBBFI","token_type":"bearer","expires_in":3600,"refresh_token":null,"error":null}

```

## The JWT Tokens

The payload of the JWT includes the following registered claims:

|CLAIM| EXPLANATION             |
|-----|-------------------------|
| iss | Always set to `zpr|bas` |
| sub | Set to the CN value     |
| aud | Always set to `zpr`     |
| iat | Token issue time        |
| exp | Token expiration time   |
| jti | A UUID                  |


The time values are seconds since the unix epoch.

In addition to the claims above, addition attributes are returned to zpr using
arbitrary claims that start with the prefix **z/**.  So in the example below
there are two attributes: `bas_id` and `color`.


```json
{
  "iss": "zpr/bas",
  "sub": "cli.zpr.org",
  "aud": "zpr",
  "exp": 1749763972,
  "iat": 1749677572,
  "jti": "6ae961e3-87ec-4fca-836a-8e2f5bff0838"
  "z/bas_id": "5678",
  "z/color": "red"
}


```