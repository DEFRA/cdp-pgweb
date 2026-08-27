# cdp-pgweb

This is a container based on [https://github.com/sosedoff/pgweb](https://github.com/sosedoff/pgweb) that runs pgweb in a way that works with the cdp-webshell launcher.

## Whats in it?

- `pgweb`: web-ui for interacting with postgres
- `aws-rds-token`: a golang helper to look up the cluster based on service name and generates a new token

## Setup/config

`pgweb` has some specific options we need to set for it to work as a replacement for cdp-webshell:

- `--listen=$PORT` must use the port set by lambda
- `-s` prevents pgweb trying to open the browser
- `--prefix=$TOKEN` makes pgweb serve traffic on a path starting with the unique prefix for that session.
- `--log-format=json` logs in a more-or-less ECS compatible format
- `--no-idle-timeout` prevents the db connection from closing when idle. Since the token only lasts 15 mins we don't want it expiring.

