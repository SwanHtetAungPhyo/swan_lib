package swan_lib

import (
	"context"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

type GraceFulShutDown struct {
	tasks []func(ctx context.Context) error
	mu    sync.Mutex
}

func New() *GraceFulShutDown {
	return &GraceFulShutDown{}
}

func (g *GraceFulShutDown) AddTask(task func(ctx context.Context) error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.tasks = append(g.tasks, task)
}

func (g *GraceFulShutDown) Run(timeout time.Duration) {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	signal.Stop(stop)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	g.mu.Lock()
	defer g.mu.Unlock()
	for i := len(g.tasks) - 1; i >= 0; i-- {
		if err := g.tasks[i](ctx); err != nil {
			log.Printf("%v", err.Error())
		}
	}
}
