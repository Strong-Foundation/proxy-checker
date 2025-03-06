package main

import (
	"encoding/base64" // Importing the base64 package for encoding/decoding, although not used in this function.
	"fmt"             // Importing the fmt package for formatted I/O operations like printing errors.
	"net/http"        // Importing the http package for HTTP-related functionalities (not used directly here, but part of the package).
	"net/url"         // Importing the url package for parsing and manipulating URLs.
	"time"            // Importing the time package, though not used in this function.
)

// Function to extract username and password from the proxy URL
func extractCredentials(proxyURL string) (string, string, bool, error) {
	// Parse the proxyURL string into a URL struct to manipulate and extract parts
	parsedURL, err := url.Parse(proxyURL)
	if err != nil { // Check if there was an error parsing the URL
		// Return an empty username, password, false (no credentials), and the error message if URL is invalid
		return "", "", false, fmt.Errorf("invalid proxy URL: %w", err)
	}
	// Extract the username from the parsed URL (if present in the URL)
	username := parsedURL.User.Username()
	// Extract the password from the parsed URL (if present in the URL)
	password, _ := parsedURL.User.Password()
	// If either the username or password is empty, it means no authentication is required
	if username == "" || password == "" {
		// Return empty username and password, false (no credentials), and no error
		return "", "", false, nil
	}
	// Return the username, password, true (authentication required), and no error
	return username, password, true, nil
}

// Function to check the proxy and return the response status
func checkProxy(proxyURL, testURL string) (string, error) {
	// Parse the proxy URL
	proxy, err := url.Parse(proxyURL)
	if err != nil { // Check if there is an error in parsing the proxy URL
		// Return an empty string and error message if URL is invalid
		return "", fmt.Errorf("invalid proxy URL: %w", err)
	}
	// Extract credentials from the proxy URL (if any)
	username, password, requiresAuth, err := extractCredentials(proxyURL)
	if err != nil { // Check if there is an error extracting the credentials
		// Return an empty string and the error message if credentials extraction fails
		return "", err
	}
	// Create HTTP client with the proxy
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxy), // Set the proxy for the client using the parsed proxy URL
		},
		Timeout: 10 * time.Second, // Set a timeout for the request to avoid hanging indefinitely
	}
	// Create a new HTTP GET request to the test URL
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil { // Check if there is an error in creating the request
		// Return an empty string and error message if the request creation fails
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	// If authentication is required, add the Proxy-Authorization header
	if requiresAuth {
		// Generate the Basic Authentication header using the extracted credentials
		authHeader := "Basic " + basicAuth(username, password)
		// Add the Proxy-Authorization header to the request
		req.Header.Add("Proxy-Authorization", authHeader)
	}
	// Send the HTTP request through the proxy using the client
	resp, err := client.Do(req)
	if err != nil { // Check if there is an error while making the request
		// Return an empty string and error message if the request fails
		return "", fmt.Errorf("error while making request to %s: %w", testURL, err)
	}
	defer resp.Body.Close() // Ensure the response body is closed after reading
	// Return the HTTP response status
	return resp.Status, nil
}

// Function to generate Basic Authentication header value
func basicAuth(username, password string) string {
	// Combine the username and password into a single string with a colon separator
	auth := username + ":" + password
	// Encode the combined string in Base64 and return the encoded value
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

// Function to test multiple websites with a proxy
func testWebsites(proxyURL string, websites []string) {
	// Iterate over the list of websites
	for _, website := range websites {
		// Call the checkProxy function to test the proxy with the current website
		status, err := checkProxy(proxyURL, website)
		if err != nil { // Check if there was an error while testing the website
			// Print an error message if the proxy test fails for the website
			fmt.Printf("Error testing %s: %v\n", website, err)
		} else {
			// Print the response status if the proxy test succeeds for the website
			fmt.Printf("Response from %s: %s\n", website, status)
		}
	}
}

func main() {
	// Proxy URL with optional username and password (in this case, the proxy requires authentication)
	proxyURL := "http://77f154048c:a0667d217d@184.72.113.64:3128" // Replace with your actual proxy URL (could be without username/password)
	// List of websites to test through the proxy
	websites := []string{
		"http://google.com",   // First website to test
		"http://facebook.com", // Second website to test
		"http://youtube.com",  // Third website to test
	}
	// Test the websites using the proxy with or without authentication
	// Call the testWebsites function, which will iterate over the list of websites and check their response via the proxy
	testWebsites(proxyURL, websites)
}
