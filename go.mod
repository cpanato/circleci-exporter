module github.com/cpanato/circleci-exporter

go 1.19

require (
	github.com/mattermost/go-circleci v0.7.1
	github.com/prometheus/client_golang v1.14.0
	github.com/prometheus/common v0.40.0
	google.golang.org/protobuf v1.33.0 // indirect
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
)

require github.com/go-kit/log v0.2.1

require (
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751 // indirect
	github.com/alecthomas/units v0.0.0-20190924025748-f65c72e2690d // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/go-logfmt/logfmt v0.5.1 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/prometheus/client_model v0.3.0 // indirect
	github.com/prometheus/procfs v0.8.0 // indirect
	golang.org/x/sys v0.3.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/mattermost/go-circleci => github.com/cpanato/go-circleci v0.7.2-0.20210913085947-42d6afbacb67
