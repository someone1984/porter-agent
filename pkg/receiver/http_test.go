package receiver

import (
	"bytes"
	"github.com/google/go-cmp/cmp"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServeHTTP(t *testing.T) {
	type args struct {
		body []byte
	}
	type want struct {
		code int
	}
	cases := map[string]struct {
		reason string
		args
		want
	}{
		"Success": {
			reason: "Should return 200 if the request is valid",
			args: args{
				body: []byte(`{"version":"4", "alerts" : [{"status":"firing", "labels":{"alertname":"TestAlert", "severity":"critical"}}]}`),
			},
			want: want{
				code: http.StatusOK,
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			serv := httptest.NewServer(NewHTTP(nil))
			defer func() { serv.Close() }()
			resp, _ := http.Post(serv.URL, "application/json", bytes.NewReader(tc.args.body))
			if diff := cmp.Diff(tc.want.code, resp.StatusCode); diff != "" {
				t.Errorf("\n%s\nServeHTTP(...): -want error, +got error:\n%s", tc.reason, diff)
			}
		})
	}
}
