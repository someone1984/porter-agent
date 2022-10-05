package logstore

import "time"

type Writer interface {
	Write(timestamp *time.Time, log string) error
}

type TailOptions struct {
	Labels               map[string]string
	Start                time.Time
	Limit                uint32
	CustomSelectorSuffix string
}

type QueryOptions struct {
	Labels               map[string]string
	Start                time.Time
	End                  time.Time
	Limit                uint32
	CustomSelectorSuffix string
}

type LabelValueOptions struct {
	Label string
	Start time.Time
	End   time.Time
}

type LogStore interface {
	Query(options QueryOptions, writer Writer, stopCh <-chan struct{}) error
	Tail(options TailOptions, writer Writer, stopCh <-chan struct{}) error
	Push(labels map[string]string, line string, t time.Time) error
	GetLabelValues(options LabelValueOptions) ([]string, error)
}
