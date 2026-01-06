module github.com/zoobzio/codec

go 1.24.0

toolchain go1.25.4

require (
	github.com/zoobzio/capitan v0.1.0
	github.com/zoobzio/codec/json v0.0.0-00010101000000-000000000000
	github.com/zoobzio/codec/msgpack v0.0.0-00010101000000-000000000000
	github.com/zoobzio/codec/xml v0.0.0-00010101000000-000000000000
	github.com/zoobzio/codec/yaml v0.0.0-00010101000000-000000000000
	github.com/zoobzio/sentinel v0.1.1
	golang.org/x/crypto v0.46.0
)

require (
	github.com/vmihailenco/msgpack/v5 v5.4.1 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace (
	github.com/zoobzio/codec/bson => ./bson
	github.com/zoobzio/codec/json => ./json
	github.com/zoobzio/codec/msgpack => ./msgpack
	github.com/zoobzio/codec/xml => ./xml
	github.com/zoobzio/codec/yaml => ./yaml
)
