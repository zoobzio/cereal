module github.com/zoobzio/cereal/msgpack

go 1.24.0

require (
	github.com/vmihailenco/msgpack/v5 v5.4.1
	github.com/zoobzio/cereal v0.0.0
)

require github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect

replace github.com/zoobzio/cereal => ../
