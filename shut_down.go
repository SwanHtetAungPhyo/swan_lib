// Package swan_lib provides various utilities and middleware for building web services in Go.
// It includes functionality for graceful shutdown, JWT authentication, CORS handling, and standardized HTTP responses.
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

// GraceFulShutDown allows graceful shutdown of services by running registered tasks during shutdown.
// It waits for termination signals (SIGINT, SIGTERM), and then executes all registered tasks within the specified timeout.
type GraceFulShutDown struct {
	tasks []func(ctx context.Context) error // Registered tasks to run during shutdown
	mu    sync.Mutex                        // Mutex to synchronize access to tasks
}

// New creates and returns a new instance of GraceFulShutDown.
func New() *GraceFulShutDown {
	return &GraceFulShutDown{}
}

// AddTask registers a new cleanup task that will be executed during the shutdown process.
// The task function receives a context, allowing it to handle cancellation or timeout.
func (g *GraceFulShutDown) AddTask(task func(ctx context.Context) error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.tasks = append(g.tasks, task)
}

// Run waits for a termination signal (SIGINT or SIGTERM) and executes all registered tasks within the given timeout duration.
// If any task returns an error, it will be logged.
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
			log.Printf("Error during shutdown task: %v", err)
		}
	}
}
