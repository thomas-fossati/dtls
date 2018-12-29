# goal

- implement [DTLS CID](https://datatracker.ietf.org/doc/draft-ietf-tls-dtls-connection-id/)

# tasks

## server side CID

### record header support
- [ ] client always sends a fixed connection id to server
  - [ ] header + CID is correctly produced by client
  - [ ] header + CID is correctly processed by server, though server ignores it
        for connection routing purposes

### negotiation support
- [ ] client offers a 0-length CID during HS, which is ignored by server
- [ ] server offers a n-length CID during HS if client offers a 0-length CID


## client side CID

Not in scope for now because the typical use case is for client migrating its
connection or client-side NAT rebinding.

