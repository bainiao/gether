package leetcode

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

type State int

const (
	Closed State = iota
	Open
	HalfOpen
)

func (s State) String() string {
	switch s {
	case Closed:
		return "Closed"
	case Open:
		return "Open"
	case HalfOpen:
		return "HalfOpen"
	default:
		return "Unknown"
	}
}

type CircuitBreaker struct {
	failureThreshold int           // failure time threshold, exceed this number then open
	successThreshold int           // half open status threshold, success times exceeds this number the close
	timeout          time.Duration // open status cool down time
	halfOpenMaxCalls int           // under half open status, the maximum tries
	state            State         // current state
	failureCount     int           // failure count
	successCount     int           // half open state, success count
	lastFailureTime  time.Time     // the last failure time
	mu               sync.Mutex    // mutex
}

func NewCircuitBreaker(failureThreshold int, timeout time.Duration, successThreshold, halfMaxThreshold int) *CircuitBreaker {
	return &CircuitBreaker{
		failureThreshold: failureThreshold,
		timeout:          timeout,
		successThreshold: successThreshold,
		halfOpenMaxCalls: halfMaxThreshold,
		state:            Closed,
	}
}
func (cb *CircuitBreaker) getState() State {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	switch cb.state {
	case Open:
		if time.Since(cb.lastFailureTime) > cb.timeout {
			cb.state = HalfOpen
			cb.successCount = 0
		}
	case Closed, HalfOpen:

	}
	return cb.state
}
func (cb *CircuitBreaker) Execute(fn func() error) error {
	state := cb.getState()
	switch state {
	case Open:
		return errors.New("circuit breaker is open: service unavailable")
	case HalfOpen:
		cb.mu.Lock()
		if cb.successCount >= cb.halfOpenMaxCalls {
			cb.mu.Unlock()
			return errors.New("circuit breaker is half-open: max trial calls reached")
		}
		cb.mu.Unlock()
	}
	err := fn()
	if err != nil {
		cb.onFailure()
		return fmt.Errorf("call failed: %w", err)
	} else {
		cb.onSuccess()
		return nil
	}
}
func (cb *CircuitBreaker) onFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	switch cb.state {
	case Closed:
		cb.failureCount++
		if cb.failureCount >= cb.failureThreshold {
			cb.state = Open
			cb.lastFailureTime = time.Now()
		}
	case HalfOpen:
		cb.state = Open
		cb.lastFailureTime = time.Now()
		cb.failureCount = 1
	}
}
func (cb *CircuitBreaker) onSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	switch cb.state {
	case Closed:
		cb.failureCount = 0
	case HalfOpen:
		cb.successCount++
		if cb.successCount >= cb.successThreshold {
			cb.state = Closed
			cb.failureCount = 0
		}
	}
}

func run() {
	cb := NewCircuitBreaker(5, 10*time.Second, 3, 2)
	failureCount := 0
	unstableService := func() error {
		failureCount++
		if failureCount <= 6 {
			return errors.New("service is down")
		}
		return nil
	}
	for i := 0; i < 15; i++ {
		err := cb.Execute(unstableService)
		fmt.Printf("%d times execution, state = %s, result = %v\n", i+1, cb.getState(), err)
		time.Sleep(1 * time.Second)
	}
}
