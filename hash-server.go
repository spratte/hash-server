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
	"regexp"
	"strconv"
	"sync"
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
	totalMsecs uint64
}

func (s *Stats) Update(msecs uint64) {
	s.mutex.Lock()
	s.Total++
	s.totalMsecs += msecs
	s.Average = int(float64(s.totalMsecs)/float64(stats.Total) + 0.5)
	s.mutex.Unlock()
}

var (
	//
	// The hash mutex is used when adding a new entry and fetching
	// an entry.
	//
	hashMutex   sync.Mutex
	hashes      []*HashedPassword

	stats       Stats
	server      *http.Server
	waitgroup   sync.WaitGroup
)

//
// checkMethod logs a message if the request method does not match the
// input parameter 'method'. If the method matches true will be
// returned, otherwise false.
//
func checkMethod(w http.ResponseWriter, req *http.Request, method string) bool {
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
// Process /hash POSTs
//
func HashStart(w http.ResponseWriter, req *http.Request) {

	waitgroup.Add(1)	// Flag that we're in here
	defer waitgroup.Done()	// and flag that we're done on exit

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
	hashes[id].wg.Add(1)	// Mark that we're this hash is not ready
	hashMutex.Unlock()
	h := hashes[id]
	h.pw = "$Hashing in progress$"
	fmt.Println(h)
	
	sendResponse(w, req, http.StatusOK, strconv.Itoa(id) + "\r\n")
	log.Printf("Hashing request:  %d", id)
	time.Sleep(5 * time.Second)

	//
	// Hash the password and update stats
	//
	sha512 := sha512.New()
	sha512.Write([]byte(password[0]))
	//fmt.Println(len(pwb), pwb)
	h.pw = base64.StdEncoding.EncodeToString(sha512.Sum(nil))
	h.wg.Done()	// Flag that hashing is done
	stats.Update(2)
	log.Printf("Hashing complete: %d", id)
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
	fmt.Println(req.Method, req.URL.Path, req.Form) //XXX
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
	fmt.Println(stats, b)
	os.Stdout.Write(b)
	sendResponse(w, req, http.StatusOK, string(b))
}

//
// Process /shutdown
//
func Shutdown(w http.ResponseWriter, req *http.Request) {

	sendResponse(w, req, http.StatusOK, "/shutdown\r\n")
	log.Printf("Shutdown received")

	waitgroup.Wait()	// Wait for everyone to finish up
        ctx, cancel := context.WithTimeout(context.Background(), 1 * time.Second)
        defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalln("Failed to close server listener - ", err)
	}
}

func Hello(w http.ResponseWriter, req *http.Request) {

	waitgroup.Add(1)	// Flag that we're in here
	defer waitgroup.Done()	// and flag that we're done on exit

	fmt.Println(req)
	io.WriteString(w, "Hello, world!\r\n")
}

func Pause(w http.ResponseWriter, req *http.Request) {

	waitgroup.Add(1)	// Flag that we're in here
	defer waitgroup.Done()	// and flag that we're done on exit

	fmt.Println(req)
	time.Sleep(10 * time.Second)
	io.WriteString(w, "/pause\r\n")
}

func main() {

	// Register handlers
	http.HandleFunc("/hello", Hello)
	http.HandleFunc("/hash",  HashStart)
	http.HandleFunc("/hash/", HashFetch)
	http.HandleFunc("/stats", HashStats)
	http.HandleFunc("/shutdown", Shutdown)
	http.HandleFunc("/pause", Pause)

	server = &http.Server{Addr: ":8080"}
	err := server.ListenAndServe()
	log.Printf("Server exiting: %s", err)
}
