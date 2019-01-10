# goal

- implement [DTLS CID](https://datatracker.ietf.org/doc/draft-ietf-tls-dtls-connection-id/)

# howto

- download udpx to simulate the NAT timeout
```
go get github.com/felipejfc/udpx
```

- put the following in a file under udpx's `config` directory:
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
