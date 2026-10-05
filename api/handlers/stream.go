package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"hoatzingenz-protection/api/models"
)

type EventHub struct {
	mu        sync.RWMutex
	listeners map[chan models.SecurityEvent]bool
}

var GlobalHub = &EventHub{
	listeners: make(map[chan models.SecurityEvent]bool),
}

func (h *EventHub) Subscribe() chan models.SecurityEvent {
	h.mu.Lock()
	defer h.mu.Unlock()
	ch := make(chan models.SecurityEvent, 20)
	h.listeners[ch] = true
	return ch
}

func (h *EventHub) Unsubscribe(ch chan models.SecurityEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.listeners[ch]; ok {
		delete(h.listeners, ch)
		close(ch)
	}
}

func (h *EventHub) Broadcast(event models.SecurityEvent) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch := range h.listeners {
		select {
		case ch <- event:
		default:
			// Non-blocking drop if channel buffer full
		}
	}
}

// Server-Sent Events (SSE) handler for real-time security alert streaming
func (h *APIHandler) HandleEventStream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}

	eventCh := GlobalHub.Subscribe()
	defer GlobalHub.Unsubscribe(eventCh)

	// Send initial connection message
	fmt.Fprintf(w, "data: %s\n\n", `{"type":"CONNECTED","message":"Live Security Alert Stream Active"}`)
	flusher.Flush()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case evt, open := <-eventCh:
			if !open {
				return
			}
			data, err := json.Marshal(evt)
			if err == nil {
				fmt.Fprintf(w, "data: %s\n\n", string(data))
				flusher.Flush()
			}

		case <-ticker.C:
			// Heartbeat comment to keep connection alive
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()

		case <-r.Context().Done():
			return
		}
	}
}
