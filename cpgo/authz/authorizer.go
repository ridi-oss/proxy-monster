package authz

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/ridi-oss/proxy-monster/cpgo/bridge"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

// The methods below are the decisions Go routes ask for (api.Authorizer).

func (d *Decider) Authorize(ctx context.Context, principal, action string, r bridge.Resource, ip string) (bool, string, error) {
	p, err := d.Parents(ctx, principal)
	if err != nil {
		return false, "", err
	}
	dec, err := d.AuthorizeAs(ctx, principal, p, action, r, Context{RequesterIP: ip})
	return dec.Allow, dec.Reason, err
}

func (d *Decider) AuthorizeEach(ctx context.Context, principal, action string, rs []bridge.Resource, ip string) ([]bool, error) {
	if len(rs) == 0 {
		return nil, nil
	}
	p, err := d.Parents(ctx, principal)
	if err != nil {
		return nil, err
	}
	out := make([]bool, len(rs))
	for i, r := range rs {
		dec, err := d.AuthorizeAs(ctx, principal, p, action, r, Context{RequesterIP: ip})
		if err != nil {
			return nil, err
		}
		out[i] = dec.Allow
	}
	return out, nil
}

// AuthorizeIn is Authorize within s: its channel, and the datasource whose context tags it derives first.
func (d *Decider) AuthorizeIn(ctx context.Context, principal, action string, r bridge.Resource, ip string, s bridge.Scope) (bool, string, error) {
	dec, err := d.AuthorizeWithContext(ctx, principal, action, r, Context{RequesterIP: ip, Channel: s.Channel}, s.Datasource, s.DatasourceTags)
	return dec.Allow, dec.Reason, err
}

// MayRequest is mayRequestOn: task.request on a live datasource with its context tags derived first.
func (d *Decider) MayRequest(ctx context.Context, principal string, id int64, ip string) (bool, error) {
	row, err := db.New(d.pool).DatasourceNameTags(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	p, err := d.Parents(ctx, principal)
	if err != nil {
		return false, err
	}
	raw := Context{RequesterIP: ip}
	if raw.Tags, err = d.ContextTags(ctx, principal, p, row.Name, row.Tags, raw); err != nil {
		return false, err
	}
	dec, err := d.DatasourceAction(ctx, principal, p, "task.request", row.Name, row.Tags, raw)
	return dec.Allow, err
}

// MayConnect is mayConnectById for each datasource: false for a missing datasource or a deactivated
// principal, else datasource.connect with the datasource's context tags derived first.
func (d *Decider) MayConnect(ctx context.Context, principal string, ids []int64, ip string) ([]bool, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	out := make([]bool, len(ids))
	deactivated, err := d.deactivated(ctx, principal)
	if err != nil || deactivated {
		return out, err
	}
	p, err := d.Parents(ctx, principal)
	if err != nil {
		return nil, err
	}
	for i, id := range ids {
		row, err := db.New(d.pool).DatasourceNameTags(ctx, id)
		if err != nil {
			continue
		}
		name, tags := row.Name, row.Tags
		raw := Context{RequesterIP: ip}
		if raw.Tags, err = d.ContextTags(ctx, principal, p, name, tags, raw); err != nil {
			return nil, err
		}
		dec, err := d.DatasourceAction(ctx, principal, p, "datasource.connect", name, tags, raw)
		if err != nil {
			return nil, err
		}
		out[i] = dec.Allow
	}
	return out, nil
}

func (d *Decider) Validate(_ context.Context, src string) ([]string, error) {
	return d.schema.Validate(src), nil
}
