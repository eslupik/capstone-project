package common

import (
	"context"
	"golang.org/x/sync/errgroup"
	"time"
)

// Why do we have a wrapper around context.Context?
// Because we want to be able to (1) log panics and (2) dump state on exit.
// However, just starting go-routines with go x() will crash the program if x() panics.
// So we need some way to reliably defer functions in many goroutines.
// Since everyone uses a context (and a context represents a unit of grouped together work, at least in some sense), it makes sense to use that.

type Context struct {
	context.Context
	deferred []func()
}

type Group struct {
	*errgroup.Group
	ctx Context
}

func (c Context) WithDefer(d func()) Context {
	c.deferred = append(c.deferred, d)
	return c
}

func (c Context) Go(f func()) {
	go func() {
		for _, d := range c.deferred {
			defer d()
		}

		f()
	}()
}

func (c Context) OnDone(f func()) {
	go func() {
		<-c.Done()
		f()
	}()
}

func Background() Context {
	return Context{
		Context: context.Background(),
	}
}
func Wrap(ctx context.Context) Context {
	return Context{
		Context: ctx,
	}
}

func WithTimeout(parent Context, timeout time.Duration) (Context, context.CancelFunc) {
	c, cancel := context.WithTimeout(parent.Context, timeout)
	parent.Context = c
	return parent, cancel
}

func WithCancel(parent Context) (Context, context.CancelFunc) {
	c, cancel := context.WithCancel(parent.Context)
	parent.Context = c
	return parent, cancel
}

func (c Context) Errgroup() (Group, Context) {
	g, newC := errgroup.WithContext(c.Context)
	c.Context = newC
	return Group{
		Group: g,
		ctx:   c,
	}, c
}

func (g Group) Go(f func() error) {
	g.Group.Go(func() error {
		for _, d := range g.ctx.deferred {
			defer d()
		}
		return f()
	})
}
