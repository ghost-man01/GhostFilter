package main

import (
	"bufio"
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
	// Authentication & Access
	"admin", "login", "signin", "auth", "oauth", "token", "key", "password", "passwd",
	"credential", "session", "verify", "account", "logout",

	// Configurations
	"config", "settings", "preferences", "env", "environment", "properties", "setup",
	".git", ".env", ".svn", ".ds_store", "manifest", "system",

	// Backups
	"backup", "bak", "archive", "restore", "dump", "snapshot", "old", "previous", "copy",
	"save",

	// APIs
	"api", "endpoint", "service", "webhook", "handler", "rest", "graphql", "ws",

	// Database
	"db", "database", "sql", "mysql", "postgres", "mongodb", "nosql", "query", "schema",
	"data", "dump",

	// Sensitive Files
	"private", "secure", "secret", "hidden", "restricted", "privileged", "confidential",
	"classified", "keypair", "certificate", "cert", "pem", "pfx", "p12", "keystore",

	// Development
	"debug", "dev", "development", "staging", "test", "testing", "qa", "prototype", "sandbox",
	"demo",

	// Logging & Monitoring
	"log", "logs", "trace", "debug", "monitor", "report", "status", "stats",

	// Payment & Financial
	"payment", "billing", "invoice", "creditcard", "card", "stripe", "paypal", "transaction",
	"bank", "checkout",

	// Miscellaneous
	"adminpanel", "control", "dashboard", "superuser", "root", "master", "manager", "upload",
	"download", "migrate", "migrate-backup", "sync", "webhook",

	// Critical file extensions
	"php", "gitignore", "bak", "env", "config", "ini", "conf", "log", "jsp", "asp", "sh", "bat",
}

// Combined regex pattern for sensitive paths
var combinedRegex = regexp.MustCompile(`(?i)/admin\b|/config\b|/debug\b|/backup\b|/auth\b|/token\b|/api\b|/private\b`)

// File extensions for image types to exclude
var excludedFileExtensions = []string{
	"png", "jpg", "jpeg", "gif", "bmp", "webp", "tiff", "ico",  // Image files
	"css", "scss", "sass", "less", "html", "htm", "js", "jsx", "ts", "tsx", "json", "xml", // Static files
	"mp3", "wav", "ogg",  // Audio files
	"mp4", "avi", "mov", "webm", "mkv", // Video files
	"woff", "woff2", "eot", "ttf", "otf", // Fonts
}

// Map to count keyword occurrences
var keywordCount = make(map[string]int)

// Mutex to protect keywordCount map from race conditions
var mu sync.Mutex

// Multi-threaded worker function
func worker(id int, jobs <-chan string, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()

	for url := range jobs {
		if isSensitive(url) && !isExcludedFile(url) {
			results <- url

			// Count keyword occurrences
			for _, keyword := range keywords {
				if strings.Contains(strings.ToLower(url), keyword) {
					mu.Lock()
					keywordCount[keyword]++
					mu.Unlock()
				}
			}
		}
	}
}

// Check if a URL is sensitive
func isSensitive(url string) bool {
	// Check for keywords
	for _, keyword := range keywords {
		if strings.Contains(strings.ToLower(url), keyword) {
			return true
		}
	}
	// Check for regex patterns
	return combinedRegex.MatchString(url)
}

// Check if the URL is an excluded file type
func isExcludedFile(url string) bool {
	for _, ext := range excludedFileExtensions {
		if strings.HasSuffix(strings.ToLower(url), "."+ext) {
			return true
		}
	}
	return false
}

// Save keyword frequency statistics to a file
func saveKeywordCounts(filePath string) {
	file, err := os.Create(filePath)
	if err != nil {
		fmt.Printf("Error creating keyword stats file: %v\n", err)
		return
	}
	defer file.Close()

	mu.Lock()
	defer mu.Unlock()

	for keyword, count := range keywordCount {
		if count > 0 {
			_, err := fmt.Fprintf(file, "%s: %d\n", keyword, count)
			if err != nil {
				fmt.Printf("Error writing to keyword stats file: %v\n", err)
			}
		}
	}
	fmt.Printf("Keyword statistics saved to: %s\n", filePath)
}

// Display help menu
func showHelp() {
	fmt.Println("GhostFilter - A tool to filter sensitive URLs from a list.")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  ghostfilter -i <input_file> -o <output_file> -k <keyword_stats_file>")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  -i, --input    Path to the input file containing URLs to filter.")
	fmt.Println("  -o, --output   Path to the output file where filtered sensitive URLs will be saved.")
	fmt.Println("  -k, --keyword  Path to the output file where keyword frequency stats will be saved.")
	fmt.Println("  -h, --help     Show this help message and exit.")
	fmt.Println()
	fmt.Println("Example usage:")
	fmt.Println("  ghostfilter -i urls.txt -o filtered_urls.txt -k keyword_stats.txt")
	fmt.Println()
}

func main() {
	// Flags for input, output, and keyword stats files
	inputFile := flag.String("i", "urls.txt", "Path to the input file containing URLs")
	outputFile := flag.String("o", "filtered_urls.txt", "Path to the output file")
	keywordFile := flag.String("k", "keyword_stats.txt", "Path to the keyword statistics output file")
	helpFlag := flag.Bool("h", false, "Show help message")
	flag.Parse()

	// Show help if -h or --help is passed
	if *helpFlag {
		showHelp()
		return
	}

	// Welcome message
	fmt.Println("╔═══════════════╗ GhostFilter ╔═══════════════╗")
	fmt.Println("💀💀💀 Developed by ghost__man01 (https://x.com/ghost__man01) 💀💀💀")

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
		counter := 0
		for scanner.Scan() {
			counter++
			jobs <- scanner.Text()
			if counter%1000 == 0 {
				fmt.Printf("Processed %d URLs...\n", counter)
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Printf("Error reading input file: %v\n", err)
		}
		close(jobs)
	}()

	// Open output file
	output, err := os.Create(*outputFile)
	if err != nil {
		fmt.Printf("Error: Unable to create output file: %v\n", err)
		os.Exit(1)
	}
	defer output.Close()

	// Collect and write results incrementally
	go func() {
		for result := range results {
			_, err := output.WriteString(result + "\n")
			if err != nil {
				fmt.Printf("Error writing to output file: %v\n", err)
			}
		}
	}()

	// Wait for workers to finish
	wg.Wait()
	close(results)

	// Save keyword counts to file
	saveKeywordCounts(*keywordFile)

	fmt.Println("Processing complete.")
}

