# castle-go

castle-go  is a go library wrapping https://castle.io API.

## Install

```
go get github.com/castle/castle-go/castle
```

## Usage

### Providing own http client

```go
castle.NewWithHTTPClient("secret-api-key", &http.Client{Timeout: time.Second * 2})
```

### Tracking properties and traits

```go
castle.Track(
		castle.EventLoginSucceeded,
		"user-123",
		map[string]string{"prop1": "propValue1"},
		map[string]string{"trait1": "traitValue1"},
		castle.ContextFromRequest(req),
	)
```

### Tracking custom events

```go
castle.Track(
		castle.Event("custom-event"),
		"user-123",
		map[string]string{"prop1": "propValue1"},
		map[string]string{"trait1": "traitValue1"},
		castle.ContextFromRequest(req),
	)
```

### Adaptive authentication

```go
decision, err := castle.Authenticate(
		castle.EventLoginSucceeded,
		"md-1",
		map[string]string{"prop1": "propValue1"},
		map[string]string{"trait1": "traitValue1"},
		castle.ContextFromRequest(req),
	)
```

### Example

```go
package main

import (
	"github.com/castle/castle-go /castle"
	"net/http"
	"log"
)

func main() {

	castle, err := castle.New("secret-api-key")

	if err != nil {
		log.Fatal(err)
	}

	http.ListenAndServe(":8080", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// authenticate user then track with castle

		decision, err := castle.AuthenticateSimple(
			castle.EventLoginSucceeded,
			"user-123",
			castle.ContextFromRequest(r),
		)

		if err != nil {
			log.Println(err)
		}

		if decision == castle.RecommendedActionChallenge {
			// challenge with MFA and track with castle

			err := castle.TrackSimple(
				castle.EventChallengeRequested,
				"user-123",
				castle.ContextFromRequest(r),
			)

			if err != nil {
				log.Println(err)
			}

			// trigger off MFA path
		}

		w.WriteHeader(http.StatusNoContent)
	}))

}
```
