[DTLS CID](https://datatracker.ietf.org/doc/draft-ietf-tls-dtls-connection-id/) implementation

# testing

## Go

Go is a prerequisite -- see https://golang.org/doc/install

## UDPX

- download udpx to simulate the NAT timeout
```
go get -u github.com/felipejfc/udpx
```

- go to the base directory
```
cd ${GOPATH}/src/github.com/felipejfc/udpx
```

- add the following mapping configuration:
```
cat << EOF > config/dtls.json
{
  "proxyConfigs": [
    {
      "bindPort": 12345,
      "clientTimeout": 3600,
      "upstreamAddress": "127.0.0.1",
      "upstreamPort": 4444,
      "name": "DTLS connection id test",
      "resolveTTL": 30000
    }
  ]
}
EOF
```

- run the proxy
```
go run main.go start -d
```
## DTLS & CID

- download this repo
```
go get -u github.com/thomas-fossati/dtls
```

- move to this repo's base directory
```
cd ${GOPATH}/src/github.com/thomas-fossati/dtls
```

- start the DTLS server in one window
```
go run cmd/listen/main.go
```

- start the DTLS client in another window
```
go run cmd/dial/main.go
```
