package drain

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestWaitReturnsAtOnceWhenIdle(t *testing.T) {
	tr := New()
	start := time.Now()
	if !tr.Wait(context.Background()) {
		t.Fatal("Wait should report drained when nothing is in flight")
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("Wait with no in-flight units should return at once, took %s", elapsed)
	}
}

func TestWaitBlocksUntilInflightDone(t *testing.T) {
	tr := New()
	tr.Add()
	go func() {
		time.Sleep(50 * time.Millisecond)
		tr.Done()
	}()
	start := time.Now()
	if !tr.Wait(context.Background()) {
		t.Fatal("Wait should report drained once the in-flight unit finished")
	}
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Fatalf("Wait returned before the in-flight unit finished (%s)", elapsed)
	}
}

func TestWaitIsBoundedByContext(t *testing.T) {
	tr := New()
	tr.Add() // never Done
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if tr.Wait(ctx) {
		t.Fatal("Wait should report NOT drained when the unit never finishes")
	}
	elapsed := time.Since(start)
	if elapsed < 90*time.Millisecond {
		t.Fatalf("Wait returned before the ctx deadline (%s)", elapsed)
	}
	if elapsed > time.Second {
		t.Fatalf("Wait overran the ctx deadline (%s)", elapsed)
	}
}

func TestBeginSignalsAndReportsDraining(t *testing.T) {
	tr := New()
	if tr.Draining() {
		t.Fatal("a new tracker must not be draining")
	}
	select {
	case <-tr.Signal():
		t.Fatal("Signal must not be closed before Begin")
	default:
	}
	tr.Begin()
	tr.Begin() // idempotent
	if !tr.Draining() {
		t.Fatal("Draining must be true after Begin")
	}
	select {
	case <-tr.Signal():
	case <-time.After(time.Second):
		t.Fatal("Signal must be closed after Begin")
	}
}

func TestConcurrent(t *testing.T) {
	tr := New()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		tr.Add()
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(10 * time.Millisecond)
			tr.Done()
		}()
	}
	if !tr.Wait(context.Background()) {
		t.Fatal("Wait should drain every in-flight unit")
	}
	wg.Wait()
}
