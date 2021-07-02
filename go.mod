module github.com/cpanato/circleci-exporter

go 1.16

require (
	github.com/go-kit/kit v0.10.0
	github.com/google/go-cmp v0.5.1 // indirect
	github.com/mattermost/go-circleci v0.7.1
	github.com/prometheus/client_golang v1.8.0
	github.com/prometheus/common v0.15.0
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	google.golang.org/protobuf v1.25.0 // indirect
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
)

replace github.com/mattermost/go-circleci => /Users/cpanato/code/src/github.com/cpanato/go-circleci
