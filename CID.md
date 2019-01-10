# goal

- implement [DTLS CID](https://datatracker.ietf.org/doc/draft-ietf-tls-dtls-connection-id/)

# testing

Go is a prerequisite -- see https://golang.org/doc/install

- download udpx to simulate the NAT timeout
```
go get -u github.com/felipejfc/udpx
```

- go to the base directory
```
cd ${GOPATH}/src/github.com/felipejfc/udpx
```

- put the following in a file (e.g., `dtls.json`) under the `config` directory:
```
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
```

- run the proxy
```
go run main.go start -d
```

- start the DTLS server
```
go run cmd/listen/main.go
```

- start the DTLS client
```
go run cmd/dial/main.go
```
