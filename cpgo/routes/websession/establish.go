package websession

import (
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/ridi-oss/proxy-monster/cpgo/session"
)

// Establish links the request's tracker (or a fresh one) to the committed session, sets the cookie, and
// tells Kotlin when the login displaced an older session.
func (a Auth) Establish(w http.ResponseWriter, r *http.Request, id int64, principal string, displaced bool) error {
	ctx := r.Context()
	ref, err := a.Sessions.Ref(ctx, r)
	if err != nil {
		return err
	}
	key := session.NewKey()
	if ref != nil {
		key = ref.Key
	}
	if err := pgx.BeginFunc(ctx, a.Pool, func(tx pgx.Tx) error { return a.Sessions.Link(ctx, tx, id, key) }); err != nil {
		return err
	}
	if displaced {
		a.signalEnded(ctx, principal)
	}
	a.Sessions.SetSessionCookie(w, key)
	return nil
}
