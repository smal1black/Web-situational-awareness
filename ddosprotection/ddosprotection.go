package ddosprotection

import (
	"fmt"
	"net/http"
	"redrock/sqlserve"
	"sync"
	"time"
)

const (
	maxRequestCount = 20
	cookieName      = "visit_count"
	cookieMaxAge    = 60
)

type IPCounter struct {
	mu      sync.Mutex
	counts  map[string]int
	blocked map[string]bool
}

func NewIPCounter() *IPCounter {
	return &IPCounter{
		counts:  make(map[string]int),
		blocked: make(map[string]bool),
	}
}

func (c *IPCounter) Increment(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counts[ip]++
}

func (c *IPCounter) GetCount(ip string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts[ip]
}

func (c *IPCounter) Block(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.blocked[ip] = true
	fmt.Printf("Blocked IP: %s\n", ip)
}

func (c *IPCounter) IsBlocked(ip string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.blocked[ip]
}

func DosProtectionMiddleware(next http.Handler, counter *IPCounter, requestIP string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//err := sqlserve.Init()
		//if err != nil {
		//	log.Fatal("Failed to initialize database:", err)
		//}
		ip := requestIP

		if counter.IsBlocked(ip) {

			err := sqlserve.WriteIP(ip)
			if err != nil {
				http.Error(w, "Failed to write blocked IP to database", http.StatusInternalServerError)
				return
			}

			http.Error(w, "IP blocked", http.StatusForbidden)
			return
		}

		count := counter.GetCount(ip)
		if count >= maxRequestCount {

			counter.Block(ip)

			err := sqlserve.WriteIP(ip)
			if err != nil {
				http.Error(w, "Failed to write blocked IP to database", http.StatusInternalServerError)
				return
			}

			http.Error(w, "IP blocked", http.StatusForbidden)
			return
		}

		counter.Increment(ip)

		if _, err := r.Cookie(cookieName); err != nil {
			cookie := &http.Cookie{
				Name:    cookieName,
				Value:   "1",
				MaxAge:  cookieMaxAge,
				Expires: time.Now().Add(time.Duration(cookieMaxAge) * time.Second),
			}
			http.SetCookie(w, cookie)
		} else {
			cookie := &http.Cookie{
				Name:    cookieName,
				Value:   "1",
				MaxAge:  cookieMaxAge,
				Expires: time.Now().Add(time.Duration(cookieMaxAge) * time.Second),
			}
			http.SetCookie(w, cookie)
		}

		next.ServeHTTP(w, r)
	})
}
