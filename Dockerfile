ARG ARCH="amd64"
ARG OS="linux"
FROM quay.io/prometheus/busybox:latest

ARG ARCH="amd64"
ARG OS="linux"
COPY .build/${OS}-${ARCH}/circleci_actions_exporter /bin/circleci_actions_exporter

USER nobody
ENTRYPOINT ["/bin/circleci_actions_exporter"]
EXPOSE     9101
