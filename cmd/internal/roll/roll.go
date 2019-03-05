package roll

import (
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"
)

type roller struct {
	writer io.WriteCloser
	open   NextFunc
	last   int
	once   sync.Once

	done    chan struct{}
	sema    chan struct{}
	written chan int
	roll    chan time.Time
	reset   chan time.Time
}

type Options struct {
	Open      NextFunc
	Timeout   time.Duration
	Interval  time.Duration
	MaxSize   int
	MaxCount  int
	Wait      bool
	KeepEmpty bool
}

var sentinel = struct{}{}

type NextFunc func(int, time.Time) (io.WriteCloser, error)

func Roll(o Options) (io.WriteCloser, error) {
	r := roller{
		open:    o.Open,
		written: make(chan int),
		roll:    make(chan time.Time, 1),
		reset:   make(chan time.Time, 1),
		sema:    make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	go r.run(o)
	if o.Wait {
		r.Rotate()
	} else {
		wc, err := r.open(1, time.Now())
		if err != nil {
			return nil, err
		}
		r.writer = wc
	}
	return &r, nil
}

func (r *roller) Write(bs []byte) (int, error) {
	select {
	case n := <-r.roll:
		n = drainRoll(r.roll, n)
		if n.IsZero() {
			n = time.Now()
		}
		r.last++
		w, err := r.open(r.last, n)
		if err != nil {
			return 0, err
		}
		r.writer = w
	default:
	}
	r.acquire()
	defer r.release()
	n, err := r.writer.Write(bs)
	if err == nil {
		go func() {
			r.written <- n
		}()
	}
	return n, err
}

func (r *roller) Close() error {
	var (
		closed bool
		err    error
	)
	r.once.Do(func() {
		close(r.done)
		err = r.closeWriter(r.writer)
		closed = true
	})
	if closed {
		return err
	}
	return fmt.Errorf("roller already closed")
}

func (r *roller) Rotate() {
	r.reset <- time.Now()
}

func (r *roller) run(o Options) {
	var (
		interval, timeout <-chan time.Time
		timer             *time.Timer
	)
	if o.Interval > 0 {
		t := time.NewTicker(o.Interval)
		interval = t.C
		defer t.Stop()
	}
	if o.Timeout > 0 {
		timer = time.NewTimer(o.Timeout)
		timeout = timer.C
		defer timer.Stop()
	}
	logger := log.New(os.Stdout, "[rotate] ", 0)
	// last := time.Now()

	var written, count int
	for {
		var (
			now     time.Time
			expired bool
			reset   bool
		)
		select {
		case <-r.done:
			return
		case n := <-timeout:
			// if n.Sub(last) < o.Timeout {
			//   continue
			// }
			expired = true
			logger.Printf("timeout rotation @%s", n.Format("2006-01-02 15:04:05"))
		case n := <-interval:
			now, reset = n, true
			logger.Printf("automatic rotation @%s", n.Format("2006-01-02 15:04:05"))
		case n := <-r.reset:
			now, reset = n, true
		case n := <-r.written:
			if n > 0 {
				count++
				written += n
			}
			if (o.MaxCount > 0 && count >= o.MaxCount) || (o.MaxSize > 0 && written > o.MaxSize) {
				now = time.Now()
				logger.Printf("threshold rotation @%s (%d - %d)", now.Format("2006-01-02 15:04:05"), written, count)
			}
		}
		if !now.IsZero() || expired {
			if written > 0 || reset {
				select {
				case r.roll <- now:
				default:
					<-r.roll
					r.roll <- now
				}

				r.closeWriter(r.writer)
			}
			written, count = 0, 0
		}
		if o.Timeout > 0 {
			timer.Reset(o.Timeout)
		}
	}
}

func (r *roller) closeWriter(old io.Closer) error {
	if old == nil {
		return nil
	}
	r.acquire()
	defer r.release()
	if f, ok := old.(interface{ Flush() error }); ok {
		f.Flush()
	}
	return old.Close()
}

func (r *roller) acquire() { r.sema <- sentinel }
func (r *roller) release() { <-r.sema }

func drainRoll(roll <-chan time.Time, n time.Time) time.Time {
	for {
		select {
		case w := <-roll:
			n = w
		default:
			return n
		}
	}
	return n
}
