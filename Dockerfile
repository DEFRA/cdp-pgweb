################################
# Webshell build stage
################################
FROM golang:1.24 AS aws-rds-tools
COPY ./aws-rds-token/ ./aws-rds-token
RUN ls 
RUN cd ./aws-rds-token && CGO_ENABLED=0 go build -ldflags="-s -w"  -trimpath -o aws-rds-token main.go

COPY ./aws-rds-proxy ./aws-rds-proxy
RUN cd ./aws-rds-proxy && CGO_ENABLED=0 go build -ldflags="-s -w"  -trimpath -o aws-rds-proxy main.go

###############################
# pgweb image
###############################
FROM sosedoff/pgweb:0.17.0

COPY --from=aws-rds-tools /go/aws-rds-token/aws-rds-token /usr/local/bin/aws-rds-token
COPY --from=aws-rds-tools /go/aws-rds-proxy/aws-rds-proxy /usr/local/bin/aws-rds-proxy
COPY entrypoint.sh /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]
