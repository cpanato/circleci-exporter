package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/mattermost/go-circleci"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	listenAddress    = kingpin.Flag("web.listen-address", "Address to listen on for web interface and telemetry.").Default(":9101").String()
	metricsPath      = kingpin.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
	circleCIToken    = kingpin.Flag("gh.circleci-token", "CircleCI Token.").Default("").String()
	circleCIOrg      = kingpin.Flag("gh.circleci-org", "CircleCI Organization.").Default("").String()
	circleCIVCSSlug  = kingpin.Flag("gh.circleci-vcs-slug", "CircleCI VCS Type (gh/bitbucket).").Default("github").String()
	circleCIProjects = kingpin.Flag("gh.circleci-projects", "CircleCI projects to track.").Default("").Strings()
)

// CircleCIExporter struct to hold some information
type CircleCIExporter struct {
	CCClient *circleci.Client
	Logger   log.Logger
}

func init() {
	prometheus.MustRegister(version.NewCollector("circleci_exporter"))
}

func main() {
	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.Version(version.Print("circleci_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promlog.New(promlogConfig)

	_ = level.Info(logger).Log("msg", "Starting circleci_exporter", "version", version.Info())
	_ = level.Info(logger).Log("build_context", version.BuildContext())

	if err := validateFlags(*circleCIToken, *circleCIOrg, *circleCIVCSSlug, *circleCIProjects); err != nil {
		_ = level.Error(logger).Log("msg", "Missing configure flags", "err", err)
		os.Exit(1)
	}

	_ = level.Info(logger).Log("msg", fmt.Sprintf("projects to watch %s", strings.Join(*circleCIProjects, ",")))

	cci, err := NewCircleCIExporter(logger)
	if err != nil {
		_ = level.Error(logger).Log("msg", "failed to create the CircleCI client")
		os.Exit(2)
	}

	prometheus.MustRegister(cci)

	srv := http.Server{
		// Timeouts
		ReadTimeout:       60 * time.Second,
		ReadHeaderTimeout: 60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		_ = level.Info(logger).Log("msg", fmt.Sprintf("Signal received: %v. Exiting...", <-signalChan))
		err := srv.Close()
		if err != nil {
			_ = level.Error(logger).Log("msg", "Error occurred while closing the server", "err", err)
		}
		os.Exit(0)
	}()

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html>
<head><title>CircleCI Exporter</title></head>
<body>
<h1>CircleCI Exporter</h1>
<p> ` + version.Print("circleci_exporter") + `  </p>
<p><a href='` + *metricsPath + `'>Metrics</a></p>
</body>
</html>
`))
	})

	listener, err := getListener(*listenAddress, logger)
	if err != nil {
		_ = level.Error(logger).Log("msg", "Could not create listener", "err", err)
		os.Exit(1)
	}

	_ = level.Info(logger).Log("msg", "CircleCI Prometheus Exporter has successfully started")
	if err := srv.Serve(listener); err != nil {
		_ = level.Error(logger).Log("msg", "Error starting HTTP server", "err", err)
		os.Exit(1)
	}
}

func getListener(listenAddress string, logger log.Logger) (net.Listener, error) {
	var listener net.Listener
	var err error

	if strings.HasPrefix(listenAddress, "unix:") {
		path, _, pathError := parseUnixSocketAddress(listenAddress)
		if pathError != nil {
			return listener, fmt.Errorf("parsing unix domain socket listen address %s failed: %w", listenAddress, pathError)
		}
		listener, err = net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	} else {
		listener, err = net.Listen("tcp", listenAddress)
	}

	if err != nil {
		return listener, err
	}

	_ = level.Info(logger).Log("msg", fmt.Sprintf("Listening on %s", listenAddress))
	return listener, nil
}

func parseUnixSocketAddress(address string) (string, string, error) {
	addressParts := strings.Split(address, ":")
	addressPartsLength := len(addressParts)

	if addressPartsLength > 3 || addressPartsLength < 1 {
		return "", "", fmt.Errorf("address for unix domain socket has wrong format")
	}

	unixSocketPath := addressParts[1]
	requestPath := ""
	if addressPartsLength == 3 {
		requestPath = addressParts[2]
	}

	return unixSocketPath, requestPath, nil
}

func validateFlags(token, org, vcsSlug string, projects []string) error {
	if token == "" {
		return errors.New("please configure the CircleCI Token")
	}

	if org == "" {
		return errors.New("please configure the CircleCI organization")
	}

	if len(projects) == 0 {
		return errors.New("please configure the CircleCI projects to track")
	}

	slugs := []string{"github", "gh", "bb", "bitbucket"}
	if vcsSlug == "" {
		return errors.New("please configure the CircleCI VCS slug, that can be github or bitbucket")
	}

	for _, slug := range slugs {
		if slug == vcsSlug {
			return nil
		}
	}

	return fmt.Errorf("circleci VCS slug %s is invalid, it only accept those: %s", vcsSlug, strings.Join(slugs, ", "))
}

func NewCircleCIExporter(logger log.Logger) (*CircleCIExporter, error) {
	client, err := circleci.NewClient(*circleCIToken, circleci.APIVersion2)
	if err != nil {
		return nil, err
	}

	return &CircleCIExporter{
		CCClient: client,
		Logger:   logger,
	}, nil
}
