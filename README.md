# castle-go

castle-go is a Go library wrapping the https://castle.io API. 

## Install

```
go get github.com/utilitywarehouse/castle-go
```

## Usage

### Providing own http client

```go
castle.NewWithHTTPClient("secret-api-key", &http.Client{Timeout: time.Second * 2})
```
