## Go WSSecurity package

A package for [WS Security](https://doc.oroinc.com/api/authentication/wsse/)

## Checking if the WSSE header is valid

```go
s := wssecurity.Security{
    Username: "my_user",
    Secret:   "my_secret",
    Lifetime: 10,
}

isAuthSuccessful, err := s.IsAuthSuccessful(header)
if err != nil {
    fmt.Printf("Error during auth %v", err)
    return false, nil
}
```

## Generate a WSSE header
```go
s := wssecurity.Security{
    Username: "my_user",
    Secret:   "my_secret",
    Lifetime: 10,
}

header, err := s.GenerateAuthHeader()
```

## Base64-encode the header

```go
encodedHeader := wssecurity.EncodeHeader(header)
```

## Decode the header if it is base64-encoded
```go
header, err := wssecurity.DecodeHeader(encodedHeader)
if err != nil {
    fmt.Printf("Error when decoding header %v", err)
    return false, nil
}
```
