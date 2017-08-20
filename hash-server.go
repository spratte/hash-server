package main

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

//
// Array of hashes indexed by job identifier
//
type HashedPassword struct {
	pw string
	wg sync.WaitGroup
}

type Stats struct {
	Total      int    `json:"total"`
	Average    int    `json:"average"`
	mutex      sync.Mutex
	sum        time.Duration
}

//
// Update the statistics with the specified elapsed time. The counter
// of hashes is incremented.
//
func (s *Stats) Update(elapsed time.Duration) {
	s.mutex.Lock()
	s.Total++
	s.sum += elapsed
	s.Average = int(float64(s.sum)/float64(stats.Total)/float64(time.Millisecond) + 0.5)
	s.mutex.Unlock()
}

var (
	//
	// The hash mutex is used when adding a new entry and fetching
	// an entry.
	//
	hashMutex   sync.Mutex
	hashes      []*HashedPassword
	shutdownReq int32	// True if shutdown has been requested

	stats       Stats
	server      *http.Server
	sigchan     chan os.Signal
	waitgroup   sync.WaitGroup
)

//
// checkMethod logs a message if the request method does not match the
// input parameter 'method'. It also checks if a shutdown is
// pending. If the method matches and no shutdown is pending, true
// will be returned, otherwise false.
//
func checkMethod(w http.ResponseWriter, req *http.Request, method string) bool {
	//
	// Check for shutdown pending
	//
	if atomic.LoadInt32(&shutdownReq) != 0 {
		sendResponse(w, req, http.StatusServiceUnavailable,
			"<p>Server shutting down<p>/r/n")
		return false
	}
	if req.Method != method {
		sendResponse(w, req, http.StatusMethodNotAllowed, "")
		return false
	}
	return true
}

//
// sendResponse sets the HTTP status code. writes the response, and
// logs it.
//
// Parameters:
//
//	w - http.ResponseWriter object
//
//	req - http.Request object
//
//	code - HTTP status to be returned
//
//	data - String containing body of the response
//
func sendResponse(w http.ResponseWriter, req *http.Request, code int, data string) {
        if code != http.StatusOK {
                http.Error(w,
                        req.Method + " " + http.StatusText(code),
                        code)
        }
 	//
	// For some reason when performing Flush() the content length
	// is not set in the header so we'll set it here.
	//
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	//
	// Write the response and flush the data if a flusher exists.
	//
	nbytes, err := io.WriteString(w, data)
	if err != nil {
		// On error, just log and ignore it - the client may
		// have disappeared
		log.Fatalln("Failed to send response - ", err)
	}

	//
	// Flush the writer if we can and ignore errors
	//
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	//
	// Log a message similar to what Apache httpd does
	//
	log.Printf("%s %s %s %d %d %s\n",
		req.RemoteAddr,
		req.Method,
		req.URL,
		code,
		nbytes,
		req.UserAgent(),
	)
}

//
// Perform a graceful shutdown
//
func shutdown() {
	atomic.StoreInt32(&shutdownReq, 1)
	waitgroup.Wait()	// Wait for everyone to finish up
        ctx, cancel := context.WithTimeout(context.Background(), 1 * time.Second)
        defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalln("Failed to close server listener - ", err)
	}
}

//
// Process /hash POSTs
//
func HashStart(w http.ResponseWriter, req *http.Request) {

	waitgroup.Add(1)	// Flag that we're in here
	defer waitgroup.Done()	// and flag that we're done on exit
	//
	// Gather request timing information. Unfortunately, the stats
	// are quite boring because hashing a small amount of data
	// takes less than a millisecond on an old computer, e.g., a
	// 32-bit 2.4GHz Pentium 4. If we look at the microseconds, or
	// increase the password size to a few megabytes, things are a
	// bit more interesting.
	//
	start := time.Now()	// Start timer
	defer func() {
		stats.Update(time.Since(start))
	} ()

	if !checkMethod(w, req, "POST") { return }

	//
	// Make sure there's a password in there. req.PostForm will
	// contain the only the parsed body, req.Form will contain
	// the parsed body and the parsed URL.
	//
	err := req.ParseForm()
	password := req.PostForm["password"]	// Returns []string
	if err != nil || len(password) == 0 {
		errmsg := "<p>No password found\r\n<p>\r\n"
		if err != nil { errmsg += err.Error() + "<p>\r\n"}
		sendResponse(w, req, http.StatusBadRequest, errmsg)
		return
	}

	//
	// Allocate a new hash entry. Use the hash mutex to allow only
	// one goroutine to use the hash array at a time.
	//
	hashMutex.Lock()
	id := len(hashes)	// The id will be the index of the next entry
	hashes = append(hashes, new(HashedPassword))
	hashes[id].wg.Add(1)	// Mark that this hash is not ready
	hashMutex.Unlock()
	h := hashes[id]
	h.pw = "$Hashing in progress$"
	sendResponse(w, req, http.StatusOK, strconv.Itoa(id) + "\r\n")
	log.Printf("Hashing request:  %d", id)
	time.Sleep(5 * time.Second)

	//
	// Hash the password and update stats
	//
	sha512 := sha512.New()
	sha512.Write([]byte(password[0]))
	h.pw = base64.StdEncoding.EncodeToString(sha512.Sum(nil))
	h.wg.Done()	// Flag that hashing is done
	log.Printf("Hashing complete: %d %s", id, time.Since(start))
}

//
// Process /hash/n GETs
//
func HashFetch(w http.ResponseWriter, req *http.Request) {

	waitgroup.Add(1)	// Flag that we're in here
	defer waitgroup.Done()	// and flag that we're done on exit

	if !checkMethod(w, req, "GET") { return }

	//
	// Parse out the hash ID
	//
	regexp := regexp.MustCompile(`/hash/(\d+)$`)
	matches := regexp.FindStringSubmatch(req.URL.Path)
	if len(matches) != 2 {
		sendResponse(w, req, http.StatusBadRequest,
			"Malformed URL - must be /hash/<id> where <id> is a number")
		return
	}
	//
	// Extract ID and validate it
	//
	id, err := strconv.Atoi(matches[1])
	hashMutex.Lock()
	if err != nil || id >= len(hashes) {
		hashMutex.Unlock()
		sendResponse(w, req, http.StatusBadRequest, "Invalid hash id")
		return
	}
	hashMutex.Unlock()
	h := hashes[id]
	//
	// Wait for hashing to complete
	//
	h.wg.Wait()	// For hashing to complete
	sendResponse(w, req, http.StatusOK, h.pw)
}

//
// Process /stats GETs
//
func HashStats(w http.ResponseWriter, req *http.Request) {

	waitgroup.Add(1)	// Flag that we're in here
	defer waitgroup.Done()	// and flag that we're done on exit

	if !checkMethod(w, req, "GET") { return }

	b, err := json.Marshal(stats)
	if err != nil {
		log.Println("JSON marshal error:", err)
	}
	sendResponse(w, req, http.StatusOK, string(b))
}

//
// Process /shutdown POST
//
func Shutdown(w http.ResponseWriter, req *http.Request) {

	waitgroup.Add(1)	// Flag that we're in here
	defer waitgroup.Done()	// and flag that we're done on exit

	if !checkMethod(w, req, "POST") { return }

	sendResponse(w, req, http.StatusOK, "<p>Shutdown requested\r\n")
	log.Printf("Shutdown received")
	//
	// Send SIGINT and let the signal handler catch it. On Linux we can do:
	//
	//	syscall.Kill(syscall.Getpid(), syscall.SIGINT)
	//
	// But Windows does not have syscall.Kill, so a somewhat tacky but portable way is to
	// just put the SIGINT into the signal channel created at startup.
	//
	sigchan<- syscall.SIGINT
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <port>\n", os.Args[0])
		os.Exit(1)
	}
	port := os.Args[1]
	//
	// Initialize shutdown flag
	//
	atomic.StoreInt32(&shutdownReq, 0)

	// Register handlers
	http.HandleFunc("/hash",  HashStart)
	http.HandleFunc("/hash/", HashFetch)
	http.HandleFunc("/stats", HashStats)
	http.HandleFunc("/shutdown", Shutdown)

	sigchan = make(chan os.Signal, 1)
	signal.Notify(sigchan, syscall.SIGINT, syscall.SIGHUP)

	server = &http.Server{Addr: ":" + port}
	//
	// Start server
	//
	go func() {
		err := server.ListenAndServe()
		if err != nil {
			log.Printf("Server exiting: %s", err)
			os.Exit(1)
		}
	} ()
	//
	// Wait for SIGINT or SIGHUP and then call shutdown
	//
	sig := <-sigchan
	log.Printf("Received %s signal", sig)
	shutdown()
	log.Println("Shutdown complete")
}
