# secure [![wercker status](https://app.wercker.com/status/2a150fdb8b40b02c22cd8152eb7984ca "wercker status")](https://app.wercker.com/project/bykey/2a150fdb8b40b02c22cd8152eb7984ca)
Martini middleware that helps enable some quick security wins.

[API Reference](http://godoc.org/github.com/martini-contrib/secure)

## Usage

```go
import (
  "github.com/go-martini/martini"
  "github.com/martini-contrib/secure"
)

func main() {
  m := martini.Classic()

  martini.Env = martini.Prod  // You have to set the environment to `production` for all of secure to work properly!

  m.Use(secure.Secure(secure.Options{
    AllowedHosts: []string{"example.com", "ssl.example.com"},
    SSLRedirect: true,
    SSLHost: "ssl.example.com",
    SSLProxyHeaders: map[string]string{"X-Forwarded-Proto": "https"},
    STSSeconds: 315360000,
    STSIncludeSubdomains: true,
    FrameDeny: true,
    ContentTypeNosniff: true,
    BrowserXssFilter: true,
    ContentSecurityPolicy: "default-src 'self'",
  }))
  m.Run()
}

```

Make sure to include the secure middleware as close to the top as possible. It's best to do the allowed hosts and SSL check before anything else.

The above example will only allow requests with a host name of 'example.com', or 'ssl.example.com'. Also if the request is not https, it will be redirected to https with the host name of 'ssl.example.com'.
After this it will add the following headers:
```
Strict-Transport-Security: 315360000; includeSubdomains
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
```

###Set the `MARTINI_ENV` environment variable to `production` when deploying!
If you don't, the AllowedHosts, SSLRedirect, and STS Header will not be in effect. This allows you to work in development/test mode and not have any annoying redirects to HTTPS (ie. development can happen on http), or block `localhost` has a bad host. If this is not the behavior you're expecting, see the `DisableProdCheck` below in the options.

You can also disable the production check for testing like so:
```go
//...
m.Use(secure.Secure(secure.Options{
    AllowedHosts: []string{"example.com", "ssl.example.com"},
    SSLRedirect: true,
    STSSeconds: 315360000,
    DisableProdCheck: martini.Env == martini.Test,
  }))
//...
```


### Options
`secure.Secure` comes with a variety of configuration options:

```go
// ...
m.Use(secure.Secure(secure.Options{
  AllowedHosts: []string{"ssl.example.com"}, // AllowedHosts is a list of fully qualified domain names that are allowed. Default is empty list, which allows any and all host names.
  SSLRedirect: true, // If SSLRedirect is set to true, then only allow https requests. Default is false.
  SSLHost: "ssl.example.com", // SSLHost is the host name that is used to redirect http requests to https. Default is "", which indicates to use the same host.
  SSLProxyHeaders: map[string]string{"X-Forwarded-Proto": "https"}, // SSLProxyHeaders is set of header keys with associated values that would indicate a valid https request. Useful when using Nginx: `map[string]string{"X-Forwarded-Proto": "https"}`. Default is blank map.
  STSSeconds: 315360000, // STSSeconds is the max-age of the Strict-Transport-Security header. Default is 0, which would NOT include the header.
  STSIncludeSubdomains: true, // If STSIncludeSubdomains is set to true, the `includeSubdomains` will be appended to the Strict-Transport-Security header. Default is false.
  FrameDeny: true, // If FrameDeny is set to true, adds the X-Frame-Options header with the value of `DENY`. Default is false.
  CustomFrameOptionsValue: "SAMEORIGIN", // CustomFrameOptionsValue allows the X-Frame-Options header value to be set with a custom value. This overrides the FrameDeny option.
  ContentTypeNosniff: true, // If ContentTypeNosniff is true, adds the X-Content-Type-Options header with the value `nosniff`. Default is false.
  BrowserXssFilter: true, // If BrowserXssFilter is true, adds the X-XSS-Protection header with the value `1; mode=block`. Default is false.
  ContentSecurityPolicy: "default-src 'self'", // ContentSecurityPolicy allows the Content-Security-Policy header value to be set with a custom value. Default is "".
  DisableProdCheck: true, // This will ignore our production check, and will follow the AllowedHosts, SSLRedirect, and STSSeconds/STSIncludeSubdomains options... even in development! This would likely only be used to mimic a production environment on your local development machine.
}))
// ...
```

### Redirecting HTTP to HTTPS
If you want to redirect all http requests to https, you can use the following example. Note that the `martini.Env` needs to be in production, otherwise the redirect will not happen (see the `MARTINI_ENV` section above for other ways around this).

```go
package main

import (
	"log"
	"net/http"

	"github.com/go-martini/martini"
	"github.com/martini-contrib/secure"
)

func main() {
	martini.Env = martini.Prod

	m := martini.New()
	m.Use(martini.Logger())
	m.Use(martini.Recovery())
	m.Use(secure.Secure(secure.Options{
		SSLRedirect:  true,
		SSLHost:      "localhost:8443",  // This is optional in production. The default behavior is to just redirect the request to the https protocol. Example: http://github.com/some_page would be redirected to https://github.com/some_page.
	}))
	m.Use(martini.Static("public"))

	r := martini.NewRouter()
	m.MapTo(r, (*martini.Routes)(nil))
	m.Action(r.Handle)

	r.Get("/", func() string {
		return "Hello world!"
	})

	// HTTP
	go func() {
		if err := http.ListenAndServe(":8080", m); err != nil {
			log.Fatal(err)
		}
	}()

	// HTTPS
	// To generate a development cert and key, run the following from your *nix terminal:
	// go run $GOROOT/src/pkg/crypto/tls/generate_cert.go --host="localhost"
	if err := http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", m); err != nil {
		log.Fatal(err)
	}
}
```

### Nginx
If you would like to add the above security rules directly to your nginx configuration, everything is below:
```
# Allowed Hosts:
if ($host !~* ^(example.com|ssl.example.com)$ ) {
    return 500;
}

# SSL Redirect:
server {
    listen      80;
    server_name example.com ssl.example.com;
    return 301 https://ssl.example.com$request_uri;
}

# Headers to be added:
add_header Strict-Transport-Security "max-age=315360000";
add_header X-Frame-Options "DENY";
add_header X-Content-Type-Options "nosniff";
add_header X-XSS-Protection "1; mode=block";
add_header Content-Security-Policy "default-src 'self'";
```

## Authors
* [Cory Jacobsen](http://github.com/unrolled)
