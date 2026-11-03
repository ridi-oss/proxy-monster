package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

type tokenCmd struct {
	sqlConn `embed:""`
}

type serviceToken struct {
	Token     string `json:"token"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	ExpiresAt string `json:"expiresAt"`
}

func (c *tokenCmd) Run() error { return c.run(context.Background(), defaultSQLEnv()) }

func (c *tokenCmd) run(ctx context.Context, env sqlEnv) error {
	outputs := env.getenv("GITHUB_OUTPUT")
	if outputs == "" {
		return errors.New("GITHUB_OUTPUT is not set: pm-ci token writes the token only to a step output, never to the log")
	}
	audience, err := audienceOf(c.sqlConn)
	if err != nil {
		return err
	}
	jwt, err := fetchOIDCToken(ctx, env, audience)
	if err != nil {
		return err
	}
	var out serviceToken
	if err := postJSON(ctx, env, c.Server, "/api/workload/exchange", "", map[string]string{"token": jwt, "purpose": "wire"}, &out); err != nil {
		return err
	}
	if out.Token == "" || strings.ContainsAny(out.Token, "\r\n") || strings.ContainsAny(out.ExpiresAt, "\r\n") {
		return errors.New("POST /api/workload/exchange: no usable token in response")
	}
	fmt.Fprintf(env.out, "::add-mask::%s\n", out.Token)
	f, err := os.OpenFile(outputs, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("GITHUB_OUTPUT: %w", err)
	}
	if _, err := fmt.Fprintf(f, "token=%s\nexpires-at=%s\nbinding=%s\n", out.Token, out.ExpiresAt, out.Name); err != nil {
		f.Close()
		return fmt.Errorf("GITHUB_OUTPUT: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("GITHUB_OUTPUT: %w", err)
	}
	fmt.Fprintf(env.out, "minted a wire token through workload binding %q; it expires %s\n", out.Name, out.ExpiresAt)
	return nil
}
