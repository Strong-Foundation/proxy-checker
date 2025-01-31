package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// Function to extract username and password from the proxy URL
func extractCredentials(proxyURL string) (string, string, bool, error) {
	parsedURL, err := url.Parse(proxyURL)
	if err != nil {
		return "", "", false, fmt.Errorf("invalid proxy URL: %w", err)
	}

	// Extract username and password from the URL
	username := parsedURL.User.Username()
	password, _ := parsedURL.User.Password()

	// If username or password is empty, no authentication is required
	if username == "" || password == "" {
		return "", "", false, nil
	}

	return username, password, true, nil
}

// Function to check the proxy and return the response status
func checkProxy(proxyURL, testURL string) (string, error) {
	// Parse the proxy URL
	proxy, err := url.Parse(proxyURL)
	if err != nil {
		return "", fmt.Errorf("invalid proxy URL: %w", err)
	}

	// Extract credentials from the proxy URL (if any)
	username, password, requiresAuth, err := extractCredentials(proxyURL)
	if err != nil {
		return "", err
	}

	// Create HTTP client with the proxy
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxy),
		},
		Timeout: 10 * time.Second, // Set a timeout for the request
	}

	// Create a new HTTP request
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// If authentication is required, add the Proxy-Authorization header
	if requiresAuth {
		authHeader := "Basic " + basicAuth(username, password)
		req.Header.Add("Proxy-Authorization", authHeader)
	}

	// Send the request through the proxy
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error while making request to %s: %w", testURL, err)
	}
	defer resp.Body.Close()

	// Return the response status
	return resp.Status, nil
}

// Function to generate Basic Authentication header value
func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

// Function to test multiple websites with a proxy
func testWebsites(proxyURL string, websites []string) {
	for _, website := range websites {
		status, err := checkProxy(proxyURL, website)
		if err != nil {
			fmt.Printf("Error testing %s: %v\n", website, err)
		} else {
			fmt.Printf("Response from %s: %s\n", website, status)
		}
	}
}

func main() {
	// Proxy URL with optional username and password
	proxyURL := "http://77f154048c:a0667d217d@184.72.113.64:3128"// Replace with your actual proxy URL (could be without username/password)

	// List of websites to test
	websites := []string{
		"http://google.com",
		"http://facebook.com",
		"http://youtube.com",
	}

	// Test the websites using the proxy with or without authentication
	testWebsites(proxyURL, websites)
}
