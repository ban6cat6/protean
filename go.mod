module github.com/ban6cat6/protean

go 1.24

retract (
	v1.4.1 // #218
	v1.4.0 // #218 panic on saveSessionTicket
)

require (
	filippo.io/edwards25519 v1.1.0
	github.com/andybalholm/brotli v1.2.0
	github.com/cloudflare/circl v1.5.0
	github.com/klauspost/compress v1.18.0
	github.com/stretchr/testify v1.10.0
	github.com/valyala/fasthttp v1.63.0
	golang.org/x/crypto v0.39.0
	golang.org/x/net v0.41.0
	golang.org/x/sys v0.33.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/kr/pretty v0.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/text v0.26.0 // indirect
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
