package ui

import (
	"sync"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/bubbly"
	"github.com/anchore/bubbly/bubbles/taskprogress"
	stereoscopeEvent "github.com/anchore/stereoscope/pkg/event"
	syftEvent "github.com/anchore/syft/syft/event"
)

var _ interface {
	bubbly.EventHandler
	bubbly.MessageListener
	bubbly.HandleWaiter
} = (*Handler)(nil)

type HandlerConfig struct {
	TitleWidth        int
	AdjustDefaultTask func(taskprogress.Model) taskprogress.Model
}

type Handler struct {
	WindowSize tea.WindowSizeMsg
	Running    *sync.WaitGroup
	Config     HandlerConfig

	bubbly.EventHandler
}

func DefaultHandlerConfig() HandlerConfig {
	return HandlerConfig{
		TitleWidth: 30,
	}
}

func New(cfg HandlerConfig) *Handler {
	d := bubbly.NewEventDispatcher()

	h := &Handler{
		EventHandler: d,
		Running:      &sync.WaitGroup{},
		Config:       cfg,
	}

	// register all supported event types with the respective handler functions
	d.AddHandlers(map[partybus.EventType]bubbly.EventHandlerFn{
		stereoscopeEvent.PullDockerImage:       h.handlePullDockerImage,
		stereoscopeEvent.PullContainerdImage:   h.handlePullContainerdImage,
		stereoscopeEvent.ReadImage:             h.handleReadImage,
		stereoscopeEvent.FetchImage:            h.handleFetchImage,
		syftEvent.PackageCatalogerStarted:      h.handlePackageCatalogerStarted,
		syftEvent.FileDigestsCatalogerStarted:  h.handleFileDigestsCatalogerStarted,
		syftEvent.FileMetadataCatalogerStarted: h.handleFileMetadataCatalogerStarted,
		syftEvent.FileIndexingStarted:          h.handleFileIndexingStarted,
		syftEvent.AttestationStarted:           h.handleAttestationStarted,
		syftEvent.CatalogerTaskStarted:         h.handleCatalogerTaskStarted,

		// deprecated
		syftEvent.SecretsCatalogerStarted: h.handleSecretsCatalogerStarted,
	})

	return h
}

func (m *Handler) OnMessage(msg tea.Msg) {
	if msg, ok := msg.(tea.WindowSizeMsg); ok {
		m.WindowSize = msg
	}
}

func (m *Handler) Wait() {
	m.Running.Wait()
}
