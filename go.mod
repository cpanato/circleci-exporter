module github.com/cpanato/circleci-exporter

go 1.18

require (
	github.com/go-kit/kit v0.12.0
	github.com/google/go-cmp v0.5.6 // indirect
	github.com/mattermost/go-circleci v0.7.1
	github.com/prometheus/client_golang v1.12.1
	github.com/prometheus/common v0.34.0
	google.golang.org/protobuf v1.27.1 // indirect
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
)

require (
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751 // indirect
	github.com/alecthomas/units v0.0.0-20190924025748-f65c72e2690d // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/go-kit/log v0.2.0 // indirect
	github.com/go-logfmt/logfmt v0.5.1 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.1 // indirect
	github.com/prometheus/client_model v0.2.0 // indirect
	github.com/prometheus/procfs v0.7.3 // indirect
	golang.org/x/sys v0.0.0-20220114195835-da31bd327af9 // indirect
)

replace github.com/mattermost/go-circleci => github.com/cpanato/go-circleci v0.7.2-0.20210913085947-42d6afbacb67
