module github.com/zoobzio/cereal/testing/integration

go 1.24.0

require (
	github.com/zoobzio/cereal v0.0.0
	github.com/zoobzio/cereal/bson v0.0.0
	github.com/zoobzio/cereal/json v0.0.0
	github.com/zoobzio/cereal/msgpack v0.0.0
	github.com/zoobzio/cereal/testing v0.0.0
	github.com/zoobzio/cereal/xml v0.0.0
	github.com/zoobzio/cereal/yaml v0.0.0
)

require (
	github.com/vmihailenco/msgpack/v5 v5.4.1 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
	github.com/zoobzio/capitan v0.1.0 // indirect
	github.com/zoobzio/sentinel v0.1.1 // indirect
	go.mongodb.org/mongo-driver v1.17.3 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace (
	github.com/zoobzio/cereal => ../..
	github.com/zoobzio/cereal/bson => ../../bson
	github.com/zoobzio/cereal/json => ../../json
	github.com/zoobzio/cereal/msgpack => ../../msgpack
	github.com/zoobzio/cereal/testing => ../
	github.com/zoobzio/cereal/xml => ../../xml
	github.com/zoobzio/cereal/yaml => ../../yaml
)
