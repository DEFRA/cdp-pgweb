package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	"github.com/aws/aws-sdk-go-v2/service/rds"
)

func main() {
	var clusterID string
	var serviceID string
	var dbUser string
	var dbPort int
	var region string
	var outputHost bool

	flag.StringVar(&clusterID, "cluster", "", "Aurora DB cluster identifier")
	flag.StringVar(&serviceID, "service", "", "Aurora DB cluster identifier (service name)")
	flag.StringVar(&dbUser, "user", "", "Database username for IAM authentication")
	flag.IntVar(&dbPort, "port", 5432, "Database port")
	flag.StringVar(&region, "region", "", "AWS Region")
	flag.BoolVar(&outputHost, "host", false, "Print the hostname instead of token")
	flag.Parse()

	if clusterID == "" && serviceID != "" {
		clusterID = serviceID
	}
	if clusterID == "" && flag.NArg() > 0 {
		clusterID = flag.Arg(0)
	}
	if clusterID == "" {
		clusterID = os.Getenv("DB_CLUSTER_IDENTIFIER")
	}
	if clusterID == "" {
		clusterID = os.Getenv("SERVICE")
	}

	if dbUser == "" && flag.NArg() > 1 {
		dbUser = flag.Arg(1)
	}
	if dbUser == "" {
		dbUser = os.Getenv("PGUSER")
	}

	if clusterID == "" || (dbUser == "" && !outputHost) {
		fmt.Fprintf(os.Stderr, "Usage: %s -service <service-name> -user <db-user> [-port <port>] [-region <region>] [-host]\n", os.Args[0])
		os.Exit(1)
	}

	ctx := context.Background()

	var optFns []func(*config.LoadOptions) error
	if region != "" {
		optFns = append(optFns, config.WithRegion(region))
	}

	cfg, err := config.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load AWS configuration: %v\n", err)
		os.Exit(1)
	}

	rdsClient := rds.NewFromConfig(cfg)

	endpointsOut, err := rdsClient.DescribeDBClusterEndpoints(ctx, &rds.DescribeDBClusterEndpointsInput{
		DBClusterIdentifier: aws.String(clusterID),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to describe db cluster endpoints: %v\n", err)
		os.Exit(1)
	}

	var writerEndpoint string
	for _, ep := range endpointsOut.DBClusterEndpoints {
		if ep.EndpointType != nil && strings.EqualFold(*ep.EndpointType, "WRITER") && ep.Endpoint != nil {
			writerEndpoint = *ep.Endpoint
			break
		}
	}

	if writerEndpoint == "" {
		clustersOut, err := rdsClient.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{
			DBClusterIdentifier: aws.String(clusterID),
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to describe db clusters: %v\n", err)
			os.Exit(1)
		}
		if len(clustersOut.DBClusters) > 0 && clustersOut.DBClusters[0].Endpoint != nil {
			writerEndpoint = *clustersOut.DBClusters[0].Endpoint
		}
	}

	if writerEndpoint == "" {
		fmt.Fprintf(os.Stderr, "writer endpoint not found for cluster %q\n", clusterID)
		os.Exit(1)
	}

	host := writerEndpoint
	portStr := strconv.Itoa(dbPort)
	if strings.Contains(writerEndpoint, ":") {
		if h, p, err := net.SplitHostPort(writerEndpoint); err == nil {
			host = h
			portStr = p
		}
	}
	endpointWithPort := net.JoinHostPort(host, portStr)
	
	if outputHost {
		fmt.Println(host)
		os.Exit(0)
	}	


	token, err := auth.BuildAuthToken(ctx, endpointWithPort, cfg.Region, dbUser, cfg.Credentials)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate db auth token: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(token)
}
