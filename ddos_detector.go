package main

import (
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// Thresholds
const requestLimit = 100            // Max requests per IP
const timeWindow = 10 * time.Second // Time window to detect DDoS

// Struct to keep track of request counts per IP
type requestData struct {
	count     int
	timestamp time.Time
}

// IPTracker holds the request data for each IP and provides a mutex for concurrency
type IPTracker struct {
	data map[string]*requestData
	mux  sync.Mutex
}

// Global IP tracker
var tracker = IPTracker{
	data: make(map[string]*requestData),
}

// Middleware to track and detect DDoS attacks
func rateLimiter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr

		tracker.mux.Lock()
		defer tracker.mux.Unlock()

		now := time.Now()
		reqData, exists := tracker.data[ip]

		// Check if IP is already tracked
		if !exists || now.Sub(reqData.timestamp) > timeWindow {
			tracker.data[ip] = &requestData{count: 1, timestamp: now}
		} else {
			reqData.count++
			if reqData.count > requestLimit {
				log.Printf("Potential DDoS detected from IP: %s (%d requests in %v)\n", ip, reqData.count, timeWindow)
			}
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	// Set up the HTTP handler
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Welcome to the server!")
	})

	// Wrap the handler with our rate limiter
	log.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", rateLimiter(http.DefaultServeMux)); err != nil {
		log.Fatalf("Server failed: %s", err)
	}
}
