# Go Library

[![Go Reference](https://pkg.go.dev/badge/github.com/mitchs-dev/library-go.svg)](https://pkg.go.dev/github.com/mitchs-dev/library-go)

## What is this?

This is a Go library which I use to provide standardizations across my Go projects. All packages included in this library are meant to be well documented so that they could be used for any Go project.

## How to use this library?

It's very easy to use this library. You can simply import the package you want to use in your project. You will want to use the following path: `github.com/mitchs-dev/library-go/<package-name>`.

For example, if you want to use the `generator` package, you can simply import it in your project like this:

```go

import (
    "github.com/mitchs-dev/library-go/generator"
    "fmt"

)

func main() {
    fmt.Println("Here's a random string: " + generator.RandomString(10))
}
```

> **Note:** Don't forget to get the package by running `go get -u github.com/mitchs-dev/library-go/generator` or `go mod tidy` if you're using Go modules.
