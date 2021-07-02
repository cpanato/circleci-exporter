package main

import (
	"github.com/go-kit/kit/log/level"
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
	//Register metrics with prometheus
	prometheus.MustRegister(TotalRunCounterVec)
	prometheus.MustRegister(TotalSuccessRunCounterVec)
	prometheus.MustRegister(TotalFailedRunCounterVec)
	prometheus.MustRegister(TotalCreditsUsedCounterVec)
}

func (cci *CircleCIExporter) Describe(ch chan<- *prometheus.Desc) {
}

func (c *CircleCIExporter) Collect(ch chan<- prometheus.Metric) {
	slug := circleci.VcsTypeGithub
	if *circleCIVCSSlug == "bitbucket" || *circleCIVCSSlug == "bb" {
		slug = circleci.VcsTypeBitbucket
	}
	for _, project := range *circleCIProjects {
		insights, err := c.CCClient.GetSummaryMetricsProjects(slug, *circleCIOrg, project, "", "", "last-24-hours", true)
		if err != nil {
			level.Error(c.Logger).Log("msg", err.Error())
			return
		}
		for _, insight := range insights.Items {
			TotalSuccessRunCounterVec.WithLabelValues(*circleCIOrg, project, insight.Name).Set(float64(insight.Metrics.SuccessfulRuns))
			TotalRunCounterVec.WithLabelValues(*circleCIOrg, project, insight.Name).Set(float64(insight.Metrics.TotalRuns))
			TotalFailedRunCounterVec.WithLabelValues(*circleCIOrg, project, insight.Name).Set(float64(insight.Metrics.FailedRuns))
			TotalCreditsUsedCounterVec.WithLabelValues(*circleCIOrg, project, insight.Name).Set(float64(insight.Metrics.TotalCreditsUsed))
		}
	}
}
