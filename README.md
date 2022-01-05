## FusionAuth Go Client ![semver 2.0.0 compliant](http://img.shields.io/badge/semver-2.0.0-brightgreen.svg?style=flat-square) [![Documentation](https://godoc.org/github.com/FusionAuth/go-client?status.svg)](http://godoc.org/github.com/FusionAuth/go-client/pkg/fusionauth)


Use this client to access the FusionAuth APIs in your Go application. For additional information and documentation on FusionAuth refer to [https://fusionauth.io](https://fusionauth.io).

## Credits
- [@medhir](https://github.com/medhir) Thank you for the initial commit and initial implementation of the Go client!
- [@markschmid](https://github.com/markschmid) Thank you for your PRs, feedback and suggestions! 
- [@MCBrandenburg](https://github.com/MCBrandenburg) Thank you for the feedback and PRs!
- [@matthewhartstonge](https://github.com/matthewhartstonge) Thank you for the PR!
- The FusionAuth team - couldn't have done it without you!

## Installation

```
go get github.com/FusionAuth/go-client/pkg/fusionauth
```

## Example Usage

The following example uses the FusionAuth Go client to create a request handling function that logs in a user: 
```go
package example

import (
    "encoding/json"
    "net/http"
    "net/url"
    "time"
    
    "github.com/FusionAuth/go-client/pkg/fusionauth"
)

const host = "http://localhost:9011"

var apiKey = "YOUR_FUSIONAUTH_API_KEY"
var httpClient = &http.Client{
	Timeout: time.Second * 10,
}

var baseURL, _ = url.Parse(host)

// Construct a new FusionAuth Client
var auth = fusionauth.NewClient(httpClient, baseURL, apiKey)

// Login logs in the user using the FusionAuth Go client library
func Login() http.HandlerFunc {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Read response body
        var credentials fusionauth.LoginRequest
        defer r.Body.Close()
        json.NewDecoder(r.Body).Decode(&credentials)
        // Use FusionAuth Go client to log in the user
        authResponse, errors, err := auth.Login(credentials)
        if err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }
        // Write the response from the FusionAuth client as JSON
        var responseJSON []byte
        if errors != nil {
            responseJSON, err = json.Marshal(errors)
        } else {
            responseJSON, err = json.Marshal(authResponse)
        }
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        w.Write(responseJSON)
    })
}
```

You can also call the API directly without logging a user in. This code uses an API key to determine the number of tenants in a FusionAuth installation.

```
package main

import (
    "net/http"
    "net/url"
    "time"
    "fmt"
    
    "github.com/FusionAuth/go-client/pkg/fusionauth"
)

const host = "http://localhost:9011"

var apiKey = "API KEY"
var httpClient = &http.Client{
    Timeout: time.Second * 10,
}

func main() {
    var baseURL, _ = url.Parse(host)

    // Construct a new FusionAuth Client
    var client = fusionauth.NewClient(httpClient, baseURL, apiKey)
    
    // for production code, don't ignore the error!
    tenantResponse, _ := client.RetrieveTenants()
    
    fmt.Print(len(tenantResponse.Tenants))
}
```

## Testing source builds

If you are modifying the go client and want to test it locally, follow these steps:

go to directory where you have go code checked out.

```
mkdir test2
cd test2
go mod init example.com/test/fusionauth
go mod tidy
vi test.go # put in your test code, in the main package
```

Then edit `go.mod` and add these lines at the bottom:

```
require (
        github.com/FusionAuth/go-client v1.0.0
)

replace (
        github.com/FusionAuth/go-client v1.0.0 => ../go-client
)
```

Then you can run it: `go run test.go # or go build`

HT https://levelup.gitconnected.com/import-and-use-local-packages-in-your-go-application-885c35e5624 for these.

## Questions and support

If you have a question or support issue regarding this client library, we'd love to hear from you.

If you have a paid edition with support included, please [open a ticket in your account portal](https://account.fusionauth.io/account/support/). Learn more about [paid editions here](https://fusionauth.io/pricing/).

Otherwise, please [post your question in the community forum](https://fusionauth.io/community/forum/).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/FusionAuth/go-client.

If you find an issue with syntax, etc - this is likely a bug in the template. Feel free to submit a PR against the Client Builder project.
- [Client Builder](https://github.com/FusionAuth/fusionauth-client-builder)
- [go.client.ftl](https://github.com/FusionAuth/fusionauth-client-builder/blob/master/src/main/client/go.client.ftl)
- [go.domain.ftl](https://github.com/FusionAuth/fusionauth-client-builder/blob/master/src/main/client/go.domain.ftl)

## License

The code is available as open source under the terms of the [Apache v2.0 License](https://opensource.org/licenses/Apache-2.0).
