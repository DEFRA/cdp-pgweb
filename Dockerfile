################################
# Webshell build stage
################################
FROM golang:1.24 AS aws-rds-token
COPY ./aws-rds-token/* .
RUN ls -la
RUN CGO_ENABLED=0 go build -ldflags="-s -w"  -trimpath -o aws-rds-token main.go

###############################
# pgweb image
###############################
FROM sosedoff/pgweb:0.17.0

COPY --from=aws-rds-token /go/aws-rds-token /usr/local/bin/aws-rds-token
COPY entrypoint.sh /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]
