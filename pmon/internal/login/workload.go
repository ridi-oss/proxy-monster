package login

import (
	"context"
	"errors"
	"net/http"
)

const WorkloadPurposeWire = "wire"

type WorkloadResult struct {
	Token     string `json:"token"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	ExpiresAt string `json:"expiresAt"`
	Service   string `json:"principal"`
}

func (r WorkloadResult) Principal() string {
	if r.Service != "" {
		return r.Service
	}
	return "workload:" + r.Name
}

func ExchangeWorkload(ctx context.Context, client *http.Client, controlPlane, jwt string) (*WorkloadResult, error) {
	var out WorkloadResult
	if err := postJSON(ctx, client, controlPlane+"/api/workload/exchange",
		map[string]string{"token": jwt, "purpose": WorkloadPurposeWire}, &out); err != nil {
		return nil, err
	}
	if out.Token == "" || out.ExpiresAt == "" {
		return nil, errors.New("the workload exchange returned no token or no expiry")
	}
	return &out, nil
}
