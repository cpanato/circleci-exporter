# CircleCI Exporter

Prometheus exporter exposing [CircleCI](https://circleci.com) metrics.


This exporter collects the insights metrics from CircleCI - [CircleCI's insights API](https://circleci.com/docs/api/v2/#tag/Insights)

## Getting Started


When configuring for an organization Access tokens must have the `repo` or `admin:org` scope.
When configuring for an user Access tokens must have the `user` scope.


### Prerequisites

To run this project, you will need a [working Go environment](https://golang.org/doc/install).

### Installing

```shell
$ go get -u github.com/cpanato/circleci-exporter
```

## Building

Build the sources with

```shell
$ make build
```

## Run the binary

```shell
$ ./circleci_exporter --gh.circleci-token="CIRCLECI_TOKEN" --gh.circleci-org="Honk-org" --gh.circleci-projects="My_Project_1" --gh.circleci-projects="My_Project_2"
```

## Docker

You can deploy this exporter using the [ghcr.io/cpanato/github_actions_exporter-linux-amd64](https://github.com/users/cpanato/packages/container/package/github_actions_exporter-linux-amd64) Docker image.

For example:

```shell
$ docker pull ghcr.io/cpanato/circleci_exporter-linux-amd64:v0.1.0

$ docker run -d -p 9101:9101 ghcr.io/cpanato/circleci_exporter-linux-amd64:v0.1.0  --gh.circleci-token="CIRCLECI_TOKEN" --gh.circleci-org="Honk-org" --gh.circleci-projects="My_Project_1" --gh.circleci-projects="My_Project_2"
```

## Testing

### Running unit tests

```shell
$ make test
```

## Contributing

Refer to [CONTRIBUTING.md](https://github.com/cpanato/circleci-exporter/blob/master/CONTRIBUTING.md).

## License

Apache License 2.0, see [LICENSE](https://github.com/cpanato/circleci-exporter/blob/master/LICENSE).
