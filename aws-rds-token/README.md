# aws-rds-token

A simple utility that calls gets a short-lived RDS token using IAM permissions.


## Why?

The AWS cli can be quite large & we only need a tiny part of it. 
The AWS CLI is also fairly slow when used in a script, the cli takes a few seconds to authenticate the call itself before returning.
This utility finds the cluster and gets a token based on a few inputs.

## Build

Run the following command to build a statically linked, stripped binary.

```
CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o aws-rds-token main.go
```

## Run


**Generate a token**

```sh
$ aws-rds-token -service my-service-name -user my_pg_username
```

**Get the clusters hostname**

```sh
$ aws-rds-token -service my-service-name -host
```
