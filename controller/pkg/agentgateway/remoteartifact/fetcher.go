package remoteartifact

import (
	"container/heap"
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"sync"
	"time"

	"istio.io/istio/pkg/util/sets"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
	"github.com/agentgateway/agentgateway/controller/pkg/logging"
)

const (
	InitialRetryDelay = 100 * time.Millisecond
	MaxRetryDelay     = 15 * time.Second
	MaxRetryShift     = 30
)

var logger = logging.New("remote_artifact")

type Request struct {
	RequestKey     remotehttp.FetchKey
	Target         remotehttp.FetchTarget
	TLSConfig      *tls.Config
	ProxyTLSConfig *tls.Config
	TTL            time.Duration
	Metadata       map[string]string
}

type FetchFunc[E any] func(context.Context, Request) (E, error)

type FetchAt struct {
	At           time.Time
	RequestKey   remotehttp.FetchKey
	Generation   uint64
	RetryAttempt int
	index        int
}

type fetchHeap []*FetchAt

func (h fetchHeap) Len() int           { return len(h) }
func (h fetchHeap) Less(i, j int) bool { return h[i].At.Before(h[j].At) }
func (h fetchHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *fetchHeap) Push(x any) {
	entry := x.(*FetchAt)
	entry.index = len(*h)
	*h = append(*h, entry)
}

func (h *fetchHeap) Pop() any {
	old := *h
	n := len(old)
	entry := old[n-1]
	entry.index = -1
	old[n-1] = nil
	*h = old[:n-1]
	return entry
}

type fetchSchedule struct {
	heap      fetchHeap
	scheduled map[remotehttp.FetchKey]*FetchAt
}

func newFetchSchedule() *fetchSchedule {
	s := &fetchSchedule{
		heap:      make(fetchHeap, 0),
		scheduled: make(map[remotehttp.FetchKey]*FetchAt),
	}
	heap.Init(&s.heap)
	return s
}

func (s *fetchSchedule) Peek() *FetchAt {
	if len(s.heap) == 0 {
		return nil
	}
	return s.heap[0]
}

func (s *fetchSchedule) PopDue(now time.Time) []FetchAt {
	var due []FetchAt
	for {
		next := s.Peek()
		if next == nil || next.At.After(now) {
			return due
		}
		entry := heap.Pop(&s.heap).(*FetchAt)
		delete(s.scheduled, entry.RequestKey)
		due = append(due, *entry)
	}
}

func (s *fetchSchedule) Schedule(requestKey remotehttp.FetchKey, generation uint64, at time.Time, retryAttempt int) {
	if scheduled := s.scheduled[requestKey]; scheduled != nil {
		scheduled.At = at
		scheduled.Generation = generation
		scheduled.RetryAttempt = retryAttempt
		heap.Fix(&s.heap, scheduled.index)
		return
	}

	entry := &FetchAt{
		At:           at,
		RequestKey:   requestKey,
		Generation:   generation,
		RetryAttempt: retryAttempt,
		index:        -1,
	}
	heap.Push(&s.heap, entry)
	s.scheduled[requestKey] = entry
}

func (s *fetchSchedule) Remove(requestKey remotehttp.FetchKey) {
	if scheduled := s.scheduled[requestKey]; scheduled != nil {
		heap.Remove(&s.heap, scheduled.index)
		delete(s.scheduled, requestKey)
	}
}

type FetchState struct {
	Request    Request
	Generation uint64
}

type Fetcher[E any] struct {
	mu          sync.Mutex
	name        string
	cache       *Cache[E]
	fetch       FetchFunc[E]
	requests    map[remotehttp.FetchKey]FetchState
	schedule    *fetchSchedule
	subscribers []chan sets.Set[remotehttp.FetchKey]
	wake        chan struct{}
	fetchedAt   func(E) time.Time
}

func NewFetcher[E any](name string, cache *Cache[E], fetch FetchFunc[E], fetchedAt func(E) time.Time) *Fetcher[E] {
	return &Fetcher[E]{
		name:        name,
		cache:       cache,
		fetch:       fetch,
		requests:    make(map[remotehttp.FetchKey]FetchState),
		schedule:    newFetchSchedule(),
		subscribers: make([]chan sets.Set[remotehttp.FetchKey], 0),
		wake:        make(chan struct{}, 1),
		fetchedAt:   fetchedAt,
	}
}

func (f *Fetcher[E]) Run(ctx context.Context) {
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()

	for {
		f.MaybeFetch(ctx)

		f.mu.Lock()
		next := f.schedule.Peek()
		var delay time.Duration
		if next == nil {
			delay = time.Hour
		} else {
			delay = time.Until(next.At)
		}
		f.mu.Unlock()

		if delay < 0 {
			delay = 0
		}
		timer.Reset(delay)

		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-f.wake:
			drainTimer(timer)
		}
	}
}

func (f *Fetcher[E]) MaybeFetch(ctx context.Context) {
	now := time.Now()
	due := f.popDue(now)
	if len(due) == 0 {
		return
	}

	updates := sets.New[remotehttp.FetchKey]()
	for _, fetch := range due {
		state, ok := f.Lookup(fetch.RequestKey)
		if !ok || state.Generation != fetch.Generation {
			continue
		}

		logger.Debug("fetching remote artifact", "artifact", f.name, "request_key", fetch.RequestKey, "target", state.Request.Target.URL)
		entry, err := f.fetch(ctx, state.Request)
		if err != nil {
			next := nextRetryDelay(fetch.RetryAttempt)
			logger.Error("error fetching remote artifact", "artifact", f.name, "request_key", fetch.RequestKey, "target", state.Request.Target.URL, "error", err, "retryAttempt", fetch.RetryAttempt, "next", next.String())
			f.scheduleAt(fetch.RequestKey, state.Generation, now.Add(next), fetch.RetryAttempt+1)
			continue
		}

		if !f.commitFetchResult(fetch.RequestKey, fetch.Generation, entry, now.Add(state.Request.TTL)) {
			continue
		}
		updates.Insert(fetch.RequestKey)
	}

	if updates.IsEmpty() {
		return
	}
	swept := f.sweepRetiredCache()
	updates.Merge(swept)
	f.notifySubscribers(updates)
}

func (f *Fetcher[E]) SubscribeToUpdates() <-chan sets.Set[remotehttp.FetchKey] {
	f.mu.Lock()
	defer f.mu.Unlock()

	subscriber := make(chan sets.Set[remotehttp.FetchKey], 1)
	f.subscribers = append(f.subscribers, subscriber)
	return subscriber
}

func (f *Fetcher[E]) AddOrUpdate(request Request) error {
	if _, err := url.Parse(request.Target.URL); err != nil {
		return fmt.Errorf("error parsing remote artifact url %w", err)
	}
	request.Metadata = cloneStringMap(request.Metadata)

	nextFetchAt := time.Now()
	if cached, ok := f.cache.Get(request.RequestKey); ok && f.fetchedAt != nil {
		if fetchedAt := f.fetchedAt(cached); !fetchedAt.IsZero() {
			expiresAt := fetchedAt.Add(request.TTL)
			if expiresAt.After(nextFetchAt) {
				nextFetchAt = expiresAt
			}
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	state := f.requests[request.RequestKey]
	state.Generation++
	state.Request = request
	f.requests[request.RequestKey] = state
	f.scheduleAtLocked(request.RequestKey, state.Generation, nextFetchAt, 0)
	return nil
}

func (f *Fetcher[E]) Remove(requestKey remotehttp.FetchKey) {
	f.mu.Lock()
	_, hadRequest := f.requests[requestKey]
	if hadRequest {
		delete(f.requests, requestKey)
		f.schedule.Remove(requestKey)
	}
	hadCache := f.cache.Delete(requestKey)
	f.mu.Unlock()

	if !hadRequest && !hadCache {
		return
	}

	f.notifySubscribers(sets.New(requestKey))
	if hadRequest {
		signalWake(f.wake)
	}
}

func (f *Fetcher[E]) Retire(requestKey remotehttp.FetchKey) {
	f.mu.Lock()
	_, hadRequest := f.requests[requestKey]
	if hadRequest {
		delete(f.requests, requestKey)
		f.schedule.Remove(requestKey)
	}
	f.mu.Unlock()

	if hadRequest {
		signalWake(f.wake)
	}
}

func (f *Fetcher[E]) SweepOrphans() {
	f.mu.Lock()
	orphans := sets.New[remotehttp.FetchKey]()
	for _, key := range f.cache.Keys() {
		if _, ok := f.requests[key]; !ok {
			orphans.Insert(key)
			f.cache.Delete(key)
		}
	}
	f.mu.Unlock()

	if !orphans.IsEmpty() {
		f.notifySubscribers(orphans)
	}
}

func (f *Fetcher[E]) Lookup(requestKey remotehttp.FetchKey) (FetchState, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	state, ok := f.requests[requestKey]
	return state, ok
}

func (f *Fetcher[E]) PeekNextForTest() *FetchAt {
	f.mu.Lock()
	defer f.mu.Unlock()
	next := f.schedule.Peek()
	if next == nil {
		return nil
	}
	copy := *next
	return &copy
}

func (f *Fetcher[E]) ScheduledLenForTest() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.schedule.heap)
}

func (f *Fetcher[E]) NotifyForTest(updates sets.Set[remotehttp.FetchKey]) {
	f.notifySubscribers(updates)
}

func (f *Fetcher[E]) commitFetchResult(requestKey remotehttp.FetchKey, generation uint64, entry E, nextFetchAt time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	state, ok := f.requests[requestKey]
	if !ok || state.Generation != generation {
		return false
	}

	f.cache.Put(entry)
	f.scheduleAtLocked(requestKey, generation, nextFetchAt, 0)
	return true
}

func (f *Fetcher[E]) sweepRetiredCache() sets.Set[remotehttp.FetchKey] {
	f.mu.Lock()
	swept := sets.New[remotehttp.FetchKey]()
	for _, key := range f.cache.Keys() {
		if _, ok := f.requests[key]; !ok {
			swept.Insert(key)
			f.cache.Delete(key)
		}
	}
	f.mu.Unlock()
	return swept
}

func (f *Fetcher[E]) popDue(now time.Time) []FetchAt {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.schedule.PopDue(now)
}

func (f *Fetcher[E]) scheduleAt(requestKey remotehttp.FetchKey, generation uint64, at time.Time, retryAttempt int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scheduleAtLocked(requestKey, generation, at, retryAttempt)
}

func (f *Fetcher[E]) scheduleAtLocked(requestKey remotehttp.FetchKey, generation uint64, at time.Time, retryAttempt int) {
	if _, ok := f.requests[requestKey]; !ok {
		return
	}

	f.schedule.Schedule(requestKey, generation, at, retryAttempt)
	signalWake(f.wake)
}

func (f *Fetcher[E]) notifySubscribers(updates sets.Set[remotehttp.FetchKey]) {
	f.mu.Lock()
	defer f.mu.Unlock()

	for _, subscriber := range f.subscribers {
		merged := cloneRequestKeySet(updates)
		select {
		case existing := <-subscriber:
			merged.Merge(existing)
		default:
		}
		subscriber <- merged
	}
}

func nextRetryDelay(retryAttempt int) time.Duration {
	shift := min(retryAttempt+1, MaxRetryShift)

	next := InitialRetryDelay * time.Duration(1<<shift)
	if next > MaxRetryDelay {
		return MaxRetryDelay
	}
	return next
}

func NextRetryDelay(retryAttempt int) time.Duration {
	return nextRetryDelay(retryAttempt)
}

func drainTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func signalWake(wake chan<- struct{}) {
	select {
	case wake <- struct{}{}:
	default:
	}
}

func cloneRequestKeySet(updates sets.Set[remotehttp.FetchKey]) sets.Set[remotehttp.FetchKey] {
	if updates == nil {
		return sets.New[remotehttp.FetchKey]()
	}
	return updates.Copy()
}

func cloneStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
