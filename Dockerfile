FROM quay.io/prometheus/busybox:latest

COPY circleci-exporter /bin/circleci-exporter

USER nobody
ENTRYPOINT ["/bin/circleci-exporter"]
EXPOSE     9101
