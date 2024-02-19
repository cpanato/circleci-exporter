module github.com/cpanato/circleci-exporter

go 1.19

require (
	github.com/mattermost/go-circleci v0.7.1
	github.com/prometheus/client_golang v1.18.0
	github.com/prometheus/common v0.47.0
	google.golang.org/protobuf v1.32.0 // indirect
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
)

require github.com/go-kit/log v0.2.1

require (
	github.com/alecthomas/kingpin/v2 v2.4.0 // indirect
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751 // indirect
	github.com/alecthomas/units v0.0.0-20211218093645-b94a6e3cc137 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/go-logfmt/logfmt v0.5.1 // indirect
	github.com/prometheus/client_model v0.5.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	github.com/xhit/go-str2duration/v2 v2.1.0 // indirect
	golang.org/x/sys v0.16.0 // indirect
)

replace github.com/mattermost/go-circleci => github.com/cpanato/go-circleci v0.7.2-0.20210913085947-42d6afbacb67
