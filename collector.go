package main

import (
	"fmt"

	"github.com/go-kit/log/level"
	"github.com/mattermost/go-circleci"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	TotalRunCounterVec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "circleci_workflow_total_runs",
		Help: "Total run of a workflow.",
	},
		[]string{"org", "repo", "workflow_name"},
	)

	TotalSuccessRunCounterVec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "circleci_workflow_total_sucessuful_runs",
		Help: "Total run of a workflow.",
	},
		[]string{"org", "repo", "workflow_name"},
	)

	TotalFailedRunCounterVec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "circleci_workflow_total_failed_runs",
		Help: "Total run of a workflow.",
	},
		[]string{"org", "repo", "workflow_name"},
	)

	TotalCreditsUsedCounterVec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "circleci_workflow_total_credits_used",
		Help: "Total run of a workflow.",
	},
		[]string{"org", "repo", "workflow_name"},
	)
)

func init() {
	// Register metrics with prometheus
	prometheus.MustRegister(TotalRunCounterVec)
	prometheus.MustRegister(TotalSuccessRunCounterVec)
	prometheus.MustRegister(TotalFailedRunCounterVec)
	prometheus.MustRegister(TotalCreditsUsedCounterVec)
}

func (cci *CircleCIExporter) Describe(ch chan<- *prometheus.Desc) {
	// noop
}

func (cci *CircleCIExporter) Collect(ch chan<- prometheus.Metric) {
	slug := circleci.VcsTypeGithub
	if *circleCIVCSSlug == "bitbucket" || *circleCIVCSSlug == "bb" {
		slug = circleci.VcsTypeBitbucket
	}

	for _, project := range *circleCIProjects {
		_ = level.Info(cci.Logger).Log("msg", fmt.Sprintf("collecting metrics for project %s", project), "org", *circleCIOrg)
		insights, err := cci.CCClient.GetSummaryMetricsProjects(slug, *circleCIOrg, project, "", "", "last-24-hours", true)
		if err != nil {
			_ = level.Error(cci.Logger).Log("msg", err.Error(), "org", *circleCIOrg, "project", project)
			continue
		}
		for _, insight := range insights.Items {
			TotalSuccessRunCounterVec.WithLabelValues(*circleCIOrg, project, insight.Name).Set(float64(insight.Metrics.SuccessfulRuns))
			TotalRunCounterVec.WithLabelValues(*circleCIOrg, project, insight.Name).Set(float64(insight.Metrics.TotalRuns))
			TotalFailedRunCounterVec.WithLabelValues(*circleCIOrg, project, insight.Name).Set(float64(insight.Metrics.FailedRuns))
			TotalCreditsUsedCounterVec.WithLabelValues(*circleCIOrg, project, insight.Name).Set(float64(insight.Metrics.TotalCreditsUsed))
		}
	}
}
