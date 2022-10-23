package lokistore

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/porter-dev/porter-agent/pkg/logstore"
	"github.com/porter-dev/porter-agent/pkg/logstore/lokistore/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type LokiStore struct {
	name          string
	address       string
	client        *Client
	pusherClient  proto.PusherClient
	querierClient proto.QuerierClient
}

type LogStoreConfig struct {
	Address     string
	HTTPAddress string
}

func New(name string, config LogStoreConfig) (*LokiStore, error) {
	address := config.Address

	if address == "" {
		address = ":3100"
	}

	client := NewClient(&LokiHTTPClientConf{
		Address: config.HTTPAddress,
	})

	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(insecure.NewCredentials()))

	if err != nil {
		return nil, fmt.Errorf("error initializing loki client with name %s. Error: %w", name, err)
	}

	return &LokiStore{
		address:       address,
		name:          name,
		pusherClient:  proto.NewPusherClient(conn),
		querierClient: proto.NewQuerierClient(conn),
		client:        client,
	}, nil
}

func (store *LokiStore) Push(labels map[string]string, line string, t time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	defer cancel()

	entry := &proto.EntryAdapter{
		Timestamp: timestamppb.New(t),
		Line:      line,
	}

	streamAdapter := &proto.StreamAdapter{
		Labels:  logstore.LabelsMapToString(labels, "=", ""),
		Entries: []*proto.EntryAdapter{entry},
	}

	_, err := store.pusherClient.Push(ctx, &proto.PushRequest{
		Streams: []*proto.StreamAdapter{streamAdapter},
	})

	if err != nil {
		return fmt.Errorf("error pushing to loki client. Error %w", err)
	}

	return nil
}

func (store *LokiStore) Query(options logstore.QueryOptions, w logstore.Writer, stopCh <-chan struct{}) error {
	qrResp, err := store.client.QueryRange(options)

	if err != nil {
		return err
	}

	for _, stream := range qrResp.Data.Result {
		for _, rawEntry := range stream.Values {
			if len(rawEntry) != 2 {
				continue
			}

			nano, err := strconv.ParseInt(rawEntry[0], 10, 64)

			if err != nil {
				continue
			}

			t := time.Unix(0, nano)

			err = w.Write(&t, rawEntry[1])

			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (store *LokiStore) Tail(options logstore.TailOptions, w logstore.Writer, stopCh <-chan struct{}) error {
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	stream, err := store.querierClient.Tail(ctx, &proto.TailRequest{
		Query: logstore.ConstructSearch(logstore.LabelsMapToString(options.Labels, "=~", options.CustomSelectorSuffix), options.SearchParam),
		Start: timestamppb.New(options.Start),
		Limit: options.Limit,
	})

	if err != nil {
		return fmt.Errorf("error streaming logs from loki store with name %s. Error: %w", store.name, err)
	}

	for {
		select {
		case <-stopCh:
			return nil
		default:
			resp, err := stream.Recv()

			if err != nil {
				if err == io.EOF {
					return nil
				}

				return err
			}

			entries := resp.Stream.GetEntries()

			for _, entry := range entries {
				t := entry.Timestamp.AsTime()

				err := w.Write(&t, entry.Line)

				if err != nil {
					return err
				}
			}
		}
	}
}

func (store *LokiStore) GetPodLabelValues(options logstore.LabelValueOptions) ([]string, error) {
	return store.getPorterPodNameSplitIndex(options, 1)
}

func (store *LokiStore) GetRevisionLabelValues(options logstore.LabelValueOptions) ([]string, error) {
	return store.getPorterPodNameSplitIndex(options, 2)
}

func (store *LokiStore) getPorterPodNameSplitIndex(options logstore.LabelValueOptions, index int) ([]string, error) {
	var matchRegexExpr string
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	defer cancel()

	if options.Revision != "" {
		matchRegexExpr = fmt.Sprintf("%s_%s-%s_%s", options.Namespace, options.PodPrefix, "[a-z0-9]+(-[a-z0-9]+)*", options.Revision)
	} else {
		matchRegexExpr = fmt.Sprintf("%s_%s-%s", options.Namespace, options.PodPrefix, "[a-z0-9]+(-[a-z0-9]+)*")
	}

	labelValues, err := store.querierClient.Label(ctx, &proto.LabelRequest{
		Name:   "porter_pod_name",
		Values: true,
		Start:  timestamppb.New(options.Start),
		End:    timestamppb.New(options.End),
	})

	if err != nil {
		return nil, err
	}

	resp := make([]string, 0)
	regex := regexp.MustCompile(matchRegexExpr)

	for _, candidatePod := range labelValues.GetValues() {
		if regex.Match([]byte(candidatePod)) {
			// strip the candidate pod with understore
			splStr := strings.Split(candidatePod, "_")

			if len(splStr) == 3 {
				resp = append(resp, splStr[index])
			}
		}
	}

	return resp, nil
}
