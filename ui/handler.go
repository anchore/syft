package ui

import (
	"context"
	"sync"

	stereoscopeEvent "github.com/anchore/stereoscope/pkg/event"
	syftEvent "github.com/anchore/syft/syft/event"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/jotframe/pkg/frame"
)

type Handler struct {
}

func NewHandler() *Handler {
	return &Handler{}
}

func (r *Handler) RespondsTo(event partybus.Event) bool {
	switch event.Type {
	case stereoscopeEvent.ReadImage, stereoscopeEvent.FetchImage, syftEvent.CatalogerStarted:
		return true
	default:
		return false
	}
}

func (r *Handler) Handle(ctx context.Context, fr *frame.Frame, event partybus.Event, wg *sync.WaitGroup) error {
	switch event.Type {
	case stereoscopeEvent.ReadImage:
		return ReadImageHandler(ctx, fr, event, wg)

	case stereoscopeEvent.FetchImage:
		return FetchImageHandler(ctx, fr, event, wg)

	case syftEvent.CatalogerStarted:
		return CatalogerStartedHandler(ctx, fr, event, wg)
	}
	return nil
}
