package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
)

// Keywords for filtering sensitive paths
var keywords = []string{
	"admin", "login", "secure", "account", "auth", "backup", "config", "token",
	"password", "secret", "private", "internal", "debug", "test", "api", "manage",
	"db", "database", "user", "signup", "register", "payment", "billing", "key", "access",
}

// Regex patterns for additional sensitive paths
var regexPatterns = []string{
	`(?i)/admin\b`, `(?i)/config\b`, `(?i)/debug\b`, `(?i)/backup\b`,
	`(?i)/auth\b`, `(?i)/token\b`, `(?i)/api\b`, `(?i)/private\b`,
}

// Multi-threaded worker function
func worker(id int, jobs <-chan string, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()

	for url := range jobs {
		if isSensitive(url) {
			results <- url
		}
	}
}

// Check if a URL is sensitive
func isSensitive(url string) bool {
	for _, keyword := range keywords {
		if strings.Contains(strings.ToLower(url), keyword) {
			return true
		}
	}
	for _, pattern := range regexPatterns {
		matched, _ := regexp.MatchString(pattern, url)
		if matched {
			return true
		}
	}
	return false
}

// Main function
func main() {
	// Flags for input and output files
	inputFile := flag.String("i", "urls.txt", "Path to the input file containing URLs")
	outputFile := flag.String("o", "filtered_urls.json", "Path to the output file")
	flag.Parse()

	// Skull and Crossbones Design for the welcome message
	fmt.Println(`
           _________
         /         \     
        |  ( )   ( )  |    
        |      ^      |     
        |     '-'     |       
         \___________/       
             💀         
  Developed by ghost_man01 | GhostFilter v1.0
	`)

	// Check input file existence
	if _, err := os.Stat(*inputFile); os.IsNotExist(err) {
		fmt.Println("Error: Input file does not exist.")
		os.Exit(1)
	}

	// Open input file
	file, err := os.Open(*inputFile)
	if err != nil {
		fmt.Printf("Error: Unable to open input file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	// Prepare channels and wait groups
	jobs := make(chan string, 100)
	results := make(chan string, 100)
	var wg sync.WaitGroup

	// Start worker pool
	numWorkers := runtime.NumCPU()
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(i, jobs, results, &wg)
	}

	// Reading URLs and feeding to jobs
	go func() {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			jobs <- scanner.Text()
		}
		close(jobs)
	}()

	// Collect results
	var sensitiveURLs []string
	go func() {
		for result := range results {
			sensitiveURLs = append(sensitiveURLs, result)
		}
	}()

	// Wait for workers to finish
	wg.Wait()
	close(results)

	// Write results to output file
	output, err := os.Create(*outputFile)
	if err != nil {
		fmt.Printf("Error: Unable to create output file: %v\n", err)
		os.Exit(1)
	}
	defer output.Close()

	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(sensitiveURLs)
	if err != nil {
		fmt.Printf("Error: Unable to write to output file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Filtering complete! Sensitive URLs saved to: %s\n", *outputFile)
}
