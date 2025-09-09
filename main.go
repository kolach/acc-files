package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/joho/godotenv"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Configuration struct
type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Port         string
	HubID        string
	ProjectID    string
}

// OAuth token response for 2-legged authentication
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// Stored token info for persistence (2-legged tokens don't have refresh tokens)
type StoredToken struct {
	AccessToken string `json:"access_token"`
	ExpiresAt   int64  `json:"expires_at"` // Unix timestamp
}

// Hub response structure
type HubsResponse struct {
	Data []Hub `json:"data"`
}

type Hub struct {
	Type       string     `json:"type"`
	ID         string     `json:"id"`
	Attributes HubAttribs `json:"attributes"`
}

type HubAttribs struct {
	Name string `json:"name"`
}

// Projects response structure
type ProjectsResponse struct {
	Data []Project `json:"data"`
}

type Project struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Attributes ProjectAttribs `json:"attributes"`
}

type ProjectAttribs struct {
	Name string `json:"name"`
}

// Folder contents response structure
type FolderContentsResponse struct {
	Data []FolderItem `json:"data"`
}

type FolderItem struct {
	Type       string           `json:"type"`
	ID         string           `json:"id"`
	Attributes FolderItemAttrib `json:"attributes"`
}

type FolderItemAttrib struct {
	Name         string    `json:"name"`
	DisplayName  string    `json:"displayName"`
	CreateTime   time.Time `json:"createTime"`
	LastModified time.Time `json:"lastModifiedTime"`
}

// Item details response structure
type ItemDetailsResponse struct {
	Data ItemDetails `json:"data"`
}

type ItemDetails struct {
	Type       string             `json:"type"`
	ID         string             `json:"id"`
	Attributes ItemDetailsAttribs `json:"attributes"`
}

type ItemDetailsAttribs struct {
	Name         string        `json:"name"`
	DisplayName  string        `json:"displayName"`
	CreateTime   time.Time     `json:"createTime"`
	LastModified time.Time     `json:"lastModifiedTime"`
	Extension    ItemExtension `json:"extension"`
}

type ItemExtension struct {
	Type    string         `json:"type"`
	Version string         `json:"version"`
	Schema  any            `json:"schema"`
	Data    map[string]any `json:"data"`
}

// Item versions response structure
type ItemVersionsResponse struct {
	Data []ItemVersion `json:"data"`
}

type ItemVersion struct {
	Type       string             `json:"type"`
	ID         string             `json:"id"`
	Attributes ItemVersionAttribs `json:"attributes"`
}

type ItemVersionAttribs struct {
	Name          string    `json:"name"`
	DisplayName   string    `json:"displayName"`
	CreateTime    time.Time `json:"createTime"`
	LastModified  time.Time `json:"lastModifiedTime"`
	VersionNumber int       `json:"versionNumber"`
	FileType      string    `json:"fileType"`
	StorageSize   int64     `json:"storageSize"`
}

// Version download info response structure
type VersionDownloadResponse struct {
	JsonAPI       map[string]any      `json:"jsonapi"`
	Links         map[string]any      `json:"links"`
	Data          VersionDownloadData `json:"data"`
	Relationships map[string]any      `json:"relationships"`
}

type VersionDownloadData struct {
	Type       string                    `json:"type"`
	ID         string                    `json:"id"`
	Attributes VersionDownloadAttributes `json:"attributes"`
}

type VersionDownloadAttributes struct {
	Name        string             `json:"name"`
	StorageSize int64              `json:"storageSize"`
	Extension   VersionDownloadExt `json:"extension"`
}

type VersionDownloadExt struct {
	Type string         `json:"type"`
	Data map[string]any `json:"data"`
}

// Global variables
var (
	config    Config
	token     *TokenResponse
	templates *template.Template
)

// Template helper functions
func initTemplates() {
	funcMap := template.FuncMap{
		"formatFileSize": formatFileSize,
		"formatTime":     formatTime,
		"lower":          strings.ToLower,
	}

	templates = template.Must(template.New("").Funcs(funcMap).ParseGlob("templates/*.html"))
}

func formatFileSize(size int64) string {
	if size <= 0 {
		return "Unknown"
	}
	if size > 1024*1024 {
		return fmt.Sprintf("%.2f MB", float64(size)/(1024*1024))
	} else if size > 1024 {
		return fmt.Sprintf("%.2f KB", float64(size)/1024)
	}
	return fmt.Sprintf("%d bytes", size)
}

func formatTime(t time.Time) string {
	return t.Format("2006-01-02 15:04:05")
}

func main() {
	log.Printf("[STARTUP] Starting Autodesk ACC File Lister application...")

	// Initialize templates
	initTemplates()
	log.Printf("[STARTUP] Templates initialized")

	// Load .env file if it exists
	err := godotenv.Load()
	if err != nil {
		log.Println("[STARTUP] No .env file found, using environment variables")
	}

	// Load configuration from environment variables
	config = Config{
		ClientID:     getEnv("APS_CLIENT_ID", ""),
		ClientSecret: getEnv("APS_CLIENT_SECRET", ""),
		RedirectURI:  getEnv("APS_REDIRECT_URI", "http://localhost:8080/callback"),
		Port:         getEnv("PORT", "8080"),
		HubID:        getEnv("APS_HUB_ID", "2c7da0c8-d4b7-48d1-9976-1954aedf4bae"),
		ProjectID:    getEnv("APS_PROJECT_ID", "5e6a3c28-74d4-4d49-ab7d-7452dafe1b6d"),
	}

	if config.ClientID == "" || config.ClientSecret == "" {
		log.Fatal("[STARTUP] FATAL: Please set APS_CLIENT_ID and APS_CLIENT_SECRET environment variables")
	}

	if config.HubID == "" || config.ProjectID == "" {
		log.Fatal("[STARTUP] FATAL: Please set APS_HUB_ID and APS_PROJECT_ID environment variables")
	}

	log.Printf("[STARTUP] Configuration loaded:")
	log.Printf("[STARTUP] - Client ID: %s***", config.ClientID[:8])
	log.Printf("[STARTUP] - Redirect URI: %s", config.RedirectURI)
	log.Printf("[STARTUP] - Port: %s", config.Port)
	log.Printf("[STARTUP] - Hub ID: %s", config.HubID)
	log.Printf("[STARTUP] - Project ID: %s", config.ProjectID)

	// Set up HTTP routes
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/projects", projectsHandler)
	http.HandleFunc("/files", filesHandler)
	http.HandleFunc("/token-status", tokenStatusHandler)
	http.HandleFunc("/versions", versionsHandler)
	http.HandleFunc("/download", downloadHandler)
	http.HandleFunc("/viewer", viewerHandler)
	http.HandleFunc("/pdf-proxy", pdfProxyHandler)

	log.Printf("[STARTUP] Routes configured:")
	log.Printf("[STARTUP] - / (home page)")
	log.Printf("[STARTUP] - /projects (project listing)")
	log.Printf("[STARTUP] - /files (file browser)")
	log.Printf("[STARTUP] - /token-status (check token status)")
	log.Printf("[STARTUP] - /versions (file versions)")
	log.Printf("[STARTUP] - /download (file download)")
	log.Printf("[STARTUP] - /viewer (PDF viewer)")
	log.Printf("[STARTUP] - /pdf-proxy (CORS proxy for S3)")

	// Get 2-legged authentication token
	if authenticate2Legged() {
		log.Printf("[STARTUP] ✅ 2-legged authentication successful!")
		fmt.Printf("🔐 Authenticated using client credentials! Visit /projects to browse files\n")
	} else {
		log.Printf("[STARTUP] ❌ 2-legged authentication failed")
		fmt.Printf("💥 Authentication failed! Check your APS_CLIENT_ID and APS_CLIENT_SECRET\n")
	}

	fmt.Printf("Server starting on port %s\n", config.Port)
	fmt.Printf("Visit: http://localhost:%s\n", config.Port)
	log.Printf("[STARTUP] Server ready and listening on port %s", config.Port)
	log.Fatal(http.ListenAndServe(":"+config.Port, nil))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	data := struct {
		IsAuthenticated bool
		AuthType        string
	}{
		IsAuthenticated: token != nil,
		AuthType:        "2-Legged (Client Credentials)",
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "home.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func projectsHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[HANDLER] Project page requested from %s", r.RemoteAddr)

	if token == nil {
		log.Printf("[HANDLER] ERROR: User not authenticated")
		http.Error(w, "Not authenticated. Please get token first.", http.StatusUnauthorized)
		return
	}

	log.Printf("[HANDLER] Fetching configured project: %s in hub: %s", config.ProjectID, config.HubID)

	// Get project details using hub ID and project ID
	projectDetails, err := getProjectDetailsWithHub(config.HubID, config.ProjectID)
	if err != nil {
		log.Printf("[HANDLER] ERROR: Failed to get project details: %v", err)
		http.Error(w, fmt.Sprintf("Failed to get project details: %v", err), http.StatusInternalServerError)
		return
	}

	// Get root folder for the project using hub ID
	rootFolderID, err := getProjectRootFolder(config.HubID, config.ProjectID)
	if err != nil {
		log.Printf("[HANDLER] ERROR: Failed to get root folder: %v", err)
		http.Error(w, fmt.Sprintf("Failed to get root folder: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[HANDLER] Successfully retrieved project details and root folder")

	// Prepare data for template
	type TemplateData struct {
		HubID           string
		ProjectID       string
		ProjectName     string
		RootFolderID    string
		ConfiguredProject string
	}

	templateData := TemplateData{
		HubID:             config.HubID,
		ProjectID:         config.ProjectID,
		ProjectName:       projectDetails.Attributes.Name,
		RootFolderID:      rootFolderID,
		ConfiguredProject: config.ProjectID,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "projects.html", templateData); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func tokenStatusHandler(w http.ResponseWriter, r *http.Request) {
	data := struct {
		HasError           bool
		Error              string
		AccessToken        string
		AuthType           string
		ExpiresAt          string
		IsExpired          bool
		SecondsExpired     int64
		SecondsUntilExpiry int64
		TestRequested      bool
		TestSuccess        bool
		TestError          string
		NewTokenExpiresIn  int
		NewAccessToken     string
	}{}

	// Set auth type
	data.AuthType = "2-Legged (Client Credentials)"

	// Load stored token
	stored, err := loadTokenFromDisk()
	if err != nil {
		data.HasError = true
		data.Error = err.Error()
	} else {
		// Populate token information
		now := time.Now().Unix()
		data.AccessToken = stored.AccessToken[:20] + "..."
		data.ExpiresAt = time.Unix(stored.ExpiresAt, 0).Format("2006-01-02 15:04:05 MST")
		data.IsExpired = stored.ExpiresAt <= now

		if data.IsExpired {
			data.SecondsExpired = now - stored.ExpiresAt
		} else {
			data.SecondsUntilExpiry = stored.ExpiresAt - now
		}
	}

	// Handle test new token request
	if r.Method == "POST" && r.FormValue("action") == "Get New Token" {
		data.TestRequested = true

		newToken, err := getClientCredentialsToken()
		if err != nil {
			data.TestError = err.Error()
		} else {
			data.TestSuccess = true
			data.NewTokenExpiresIn = newToken.ExpiresIn
			data.NewAccessToken = newToken.AccessToken[:20] + "..."

			// Update global token and save to disk
			token = newToken
			saveErr := saveTokenToDisk(newToken)
			if saveErr != nil {
				data.TestError = "Token obtained but failed to save: " + saveErr.Error()
			}
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "token-status.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func versionsHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[HANDLER] Versions page requested from %s", r.RemoteAddr)

	if token == nil {
		log.Printf("[HANDLER] ERROR: User not authenticated")
		http.Error(w, "Not authenticated. Please login first.", http.StatusUnauthorized)
		return
	}

	projectID := r.URL.Query().Get("projectId")
	itemID := r.URL.Query().Get("itemId")
	fileName := r.URL.Query().Get("fileName")

	log.Printf("[HANDLER] Versions page parameters - projectId: %s, itemId: %s, fileName: %s", projectID, itemID, fileName)

	if projectID == "" || itemID == "" {
		log.Printf("[HANDLER] ERROR: Missing required parameters - projectId: %s, itemId: %s", projectID, itemID)
		http.Error(w, "projectId and itemId parameters required", http.StatusBadRequest)
		return
	}

	log.Printf("[HANDLER] Fetching versions for item: %s (%s)", fileName, itemID)

	// Get item versions
	versions, err := getItemVersions(projectID, itemID)
	if err != nil {
		log.Printf("[HANDLER] ERROR: Failed to get item versions: %v", err)
		http.Error(w, fmt.Sprintf("Failed to get item versions: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[HANDLER] Successfully retrieved %d versions for item", len(versions.Data))

	// Prepare data for template
	data := struct {
		FileName  string
		ItemID    string
		ProjectID string
		Versions  []ItemVersion
	}{
		FileName:  fileName,
		ItemID:    itemID,
		ProjectID: projectID,
		Versions:  versions.Data,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "versions.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[HANDLER] Download requested from %s", r.RemoteAddr)

	if token == nil {
		log.Printf("[HANDLER] ERROR: User not authenticated")
		http.Error(w, "Not authenticated. Please login first.", http.StatusUnauthorized)
		return
	}

	projectID := r.URL.Query().Get("projectId")
	itemID := r.URL.Query().Get("itemId")
	versionNumber := r.URL.Query().Get("versionNumber")
	fileName := r.URL.Query().Get("fileName")

	if projectID == "" || itemID == "" {
		log.Printf("[HANDLER] ERROR: Missing required parameters - projectId: %s, itemId: %s", projectID, itemID)
		http.Error(w, "projectId and itemId parameters required", http.StatusBadRequest)
		return
	}

	log.Printf("[HANDLER] Downloading file: %s (item: %s, version: %s)", fileName, itemID, versionNumber)

	// Step 1: Get versions for the item to find the specific version with storage info
	versions, err := getItemVersions(projectID, itemID)
	if err != nil {
		log.Printf("[HANDLER] ERROR: Failed to get item versions: %v", err)
		http.Error(w, fmt.Sprintf("Failed to get item versions: %v", err), http.StatusInternalServerError)
		return
	}

	// Step 2: Find the requested version and extract storage information
	var targetVersion *ItemVersion

	for _, version := range versions.Data {
		// If version number specified, match it; otherwise use the latest (first) version
		if versionNumber == "" || fmt.Sprintf("%d", version.Attributes.VersionNumber) == versionNumber {
			targetVersion = &version
			break
		}
	}

	if targetVersion == nil {
		log.Printf("[HANDLER] ERROR: Version not found")
		http.Error(w, "Requested version not found", http.StatusNotFound)
		return
	}

	log.Printf("[HANDLER] Found target version %d, getting detailed info with storage...", targetVersion.Attributes.VersionNumber)

	// Step 3: Get detailed version info that includes storage relationship
	versionDetails, err := getVersionWithStorage(projectID, targetVersion.ID)
	if err != nil {
		log.Printf("[HANDLER] ERROR: Failed to get version storage details: %v", err)
		http.Error(w, fmt.Sprintf("Failed to get version storage details: %v", err), http.StatusInternalServerError)
		return
	}

	// Step 4: Extract storage URN from version details
	storageURN, err := extractStorageURNFromVersion(versionDetails)
	if err != nil {
		log.Printf("[HANDLER] ERROR: Failed to extract storage URN: %v", err)
		http.Error(w, fmt.Sprintf("Failed to extract storage URN: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[HANDLER] Extracted storage URN: %s", storageURN)

	// Step 5: Parse bucket and object key from storage URN
	bucket, objectKey, err := parseStorageURN(storageURN)
	if err != nil {
		log.Printf("[HANDLER] ERROR: Failed to parse storage URN: %v", err)
		http.Error(w, fmt.Sprintf("Failed to parse storage URN: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[HANDLER] Parsed storage - bucket: %s, objectKey: %s", bucket, objectKey)

	// Step 6: Get signed S3 download URL from OSS API
	signedURL, err := getOSSSignedDownloadURL(bucket, objectKey)
	if err != nil {
		log.Printf("[HANDLER] ERROR: Failed to get signed download URL: %v", err)
		http.Error(w, fmt.Sprintf("Failed to get signed download URL: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[HANDLER] Got signed download URL, streaming file to client...")

	// Step 7: Stream the file from S3 to the client
	err = streamFileDownload(w, signedURL, fileName)
	if err != nil {
		log.Printf("[HANDLER] ERROR: Failed to stream file: %v", err)
		// Don't call http.Error here as we may have already started writing the response
		return
	}

	log.Printf("[HANDLER] Successfully streamed file: %s", fileName)
}

func filesHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[HANDLER] Files page requested from %s", r.RemoteAddr)

	if token == nil {
		log.Printf("[HANDLER] ERROR: User not authenticated")
		http.Error(w, "Not authenticated. Please get token first.", http.StatusUnauthorized)
		return
	}

	// Use configured project ID
	projectID := config.ProjectID
	folderID := r.URL.Query().Get("folderId")

	log.Printf("[HANDLER] Using configured project: %s, folder: %s", projectID, folderID)

	var targetFolderID string
	var err error

	if folderID != "" {
		log.Printf("[HANDLER] Navigating to specific folder: %s in project %s", folderID, projectID)
		targetFolderID = folderID
	} else {
		log.Printf("[HANDLER] Getting root folder for project %s", projectID)
		// Get project root folder
		targetFolderID, err = getProjectRootFolderDirect(projectID)
		if err != nil {
			log.Printf("[HANDLER] ERROR: Failed to get root folder: %v", err)
			http.Error(w, fmt.Sprintf("Failed to get root folder: %v", err), http.StatusInternalServerError)
			return
		}
	}

	log.Printf("[HANDLER] Fetching contents for folder: %s", targetFolderID)

	// Get folder contents
	contents, err := getFolderContents(projectID, targetFolderID)
	if err != nil {
		log.Printf("[HANDLER] ERROR: Failed to get folder contents: %v", err)
		http.Error(w, fmt.Sprintf("Failed to get folder contents: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[HANDLER] Successfully retrieved %d items from folder", len(contents.Data))

	// Collect URNs for all files (non-folders) in this folder
	var fileURNs []string
	for _, item := range contents.Data {
		if item.Type != "folders" {
			fileURNs = append(fileURNs, item.ID)
			log.Printf("[HANDLER] Found file URN: %s (%s)", item.ID, item.Attributes.DisplayName)
		}
	}

	log.Printf("[HANDLER] Collected %d file URNs for batch custom attributes lookup", len(fileURNs))

	// Get custom attributes for all files in one batch request
	var batchCustomAttributes map[string]any
	if len(fileURNs) > 0 {
		batchCustomAttributes, err = getBatchCustomAttributes(projectID, fileURNs)
		if err != nil {
			log.Printf("[HANDLER] WARNING: Batch custom attributes request failed: %v", err)
			batchCustomAttributes = make(map[string]any)
		}
	}

	// Prepare enhanced items with custom attributes
	type EnhancedFolderItem struct {
		FolderItem
		CustomAttributes          bool
		CustomAttributesFormatted string
	}

	var enhancedItems []EnhancedFolderItem
	for _, item := range contents.Data {
		enhanced := EnhancedFolderItem{FolderItem: item}

		if item.Type != "folders" {
			if fileAttrs, exists := batchCustomAttributes[item.ID]; exists {
				log.Printf("[HANDLER] SUCCESS: Found batch custom attributes for %s", item.Attributes.DisplayName)
				enhanced.CustomAttributes = true
				enhanced.CustomAttributesFormatted = formatCustomAttributesFromBatch(fileAttrs)
			} else {
				log.Printf("[HANDLER] No custom attributes found in batch for %s", item.Attributes.DisplayName)
				enhanced.CustomAttributes = false
			}
		}

		enhancedItems = append(enhancedItems, enhanced)
	}

	// Prepare data for template
	data := struct {
		HubID         string
		ProjectID     string
		IsRootFolder  bool
		FileCount     int
		HasAttributes bool
		Items         []EnhancedFolderItem
	}{
		HubID:         config.HubID,
		ProjectID:     projectID,
		IsRootFolder:  folderID == "",
		FileCount:     len(fileURNs),
		HasAttributes: len(batchCustomAttributes) > 0,
		Items:         enhancedItems,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "files.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// 2-legged authentication using client credentials
func authenticate2Legged() bool {
	log.Printf("[AUTH] Starting 2-legged authentication with client credentials")

	// First try to use stored token if it's still valid
	stored, err := loadTokenFromDisk()
	if err == nil {
		// Check if current access token is still valid (with 5 minute buffer)
		if stored.ExpiresAt > time.Now().Unix()+300 {
			log.Printf("[AUTH] Using valid stored token")
			token = &TokenResponse{
				AccessToken: stored.AccessToken,
				TokenType:   "Bearer",
				ExpiresIn:   int(stored.ExpiresAt - time.Now().Unix()),
			}
			return true
		}
	}

	// Get new token using client credentials
	log.Printf("[AUTH] Getting new 2-legged token")
	newToken, err := getClientCredentialsToken()
	if err != nil {
		log.Printf("[AUTH] ERROR: Failed to get 2-legged token: %v", err)
		return false
	}

	token = newToken

	// Save token to disk
	err = saveTokenToDisk(newToken)
	if err != nil {
		log.Printf("[AUTH] WARNING: Failed to save token: %v", err)
	}

	return true
}

func getClientCredentialsToken() (*TokenResponse, error) {
	log.Printf("[AUTH] Requesting 2-legged token using client credentials")

	// Step 1: Create Base64 encoded credentials (CLIENT_ID:CLIENT_SECRET)
	credentials := fmt.Sprintf("%s:%s", config.ClientID, config.ClientSecret)
	encodedCredentials := base64.StdEncoding.EncodeToString([]byte(credentials))
	log.Printf("[AUTH] Created Base64 encoded credentials")

	// Step 2: Prepare form data
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("scope", "data:read")

	log.Printf("[AUTH] Making POST request to token endpoint")
	req, err := http.NewRequest("POST", "https://developer.api.autodesk.com/authentication/v2/token", strings.NewReader(data.Encode()))
	if err != nil {
		log.Printf("[AUTH] ERROR: Failed to create token request: %v", err)
		return nil, err
	}

	// Step 3: Set headers with Authorization Basic
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Basic "+encodedCredentials)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[AUTH] ERROR: Token request failed: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	log.Printf("[AUTH] Token response received with status: %d", resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[AUTH] ERROR: Failed to read token response: %v", err)
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("[AUTH] ERROR: Token request failed with HTTP %d: %s", resp.StatusCode, string(body))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	err = json.Unmarshal(body, &tokenResp)
	if err != nil {
		log.Printf("[AUTH] ERROR: Failed to parse token response: %v", err)
		return nil, err
	}

	log.Printf("[AUTH] 2-legged token obtained successfully (expires in %d seconds)", tokenResp.ExpiresIn)
	return &tokenResp, nil
}

func makeAuthorizedRequest(url string) (*http.Response, error) {
	log.Printf("[API] Making authorized request to: %s", url)

	// Try request with current token first
	resp, err := doAuthorizedRequest(url)
	if err != nil {
		return nil, err
	}

	// If we get 401 (token expired), get a new token and retry once
	if resp.StatusCode == 401 {
		log.Printf("[API] Access token expired (401), getting new 2-legged token...")
		resp.Body.Close() // Close the 401 response

		// Get new token using client credentials
		newToken, err := getClientCredentialsToken()
		if err != nil {
			log.Printf("[API] ERROR: Failed to get new 2-legged token: %v", err)
			return resp, nil // Return original 401 response
		}

		// Update global token
		token = newToken

		// Save new token
		saveErr := saveTokenToDisk(newToken)
		if saveErr != nil {
			log.Printf("[API] WARNING: Failed to save new token: %v", saveErr)
		}

		log.Printf("[API] Successfully obtained new token, retrying request...")

		// Retry the request with new token
		return doAuthorizedRequest(url)
	}

	return resp, nil
}

func doAuthorizedRequest(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("[API] ERROR: Failed to create request: %v", err)
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	log.Printf("[API] Using Bearer token: %s***", token.AccessToken[:20])

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[API] ERROR: Request failed: %v", err)
		return nil, err
	}

	log.Printf("[API] Response received with status: %d", resp.StatusCode)
	return resp, nil
}

func getHubs() (*HubsResponse, error) {
	log.Printf("[API] Fetching user hubs...")

	resp, err := makeAuthorizedRequest("https://developer.api.autodesk.com/project/v1/hubs")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[API] ERROR: Failed to read hubs response: %v", err)
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("[API] ERROR: Get hubs failed with HTTP %d: %s", resp.StatusCode, string(body))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var hubs HubsResponse
	err = json.Unmarshal(body, &hubs)
	if err != nil {
		log.Printf("[API] ERROR: Failed to parse hubs response: %v", err)
		return nil, err
	}

	log.Printf("[API] Successfully retrieved %d hubs", len(hubs.Data))
	return &hubs, err
}

func getProjects(hubID string) (*ProjectsResponse, error) {
	log.Printf("[API] Fetching projects for hub: %s", hubID)

	url := fmt.Sprintf("https://developer.api.autodesk.com/project/v1/hubs/%s/projects", hubID)
	resp, err := makeAuthorizedRequest(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[API] ERROR: Failed to read projects response: %v", err)
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("[API] ERROR: Get projects failed with HTTP %d: %s", resp.StatusCode, string(body))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var projects ProjectsResponse
	err = json.Unmarshal(body, &projects)
	if err != nil {
		log.Printf("[API] ERROR: Failed to parse projects response: %v", err)
		return nil, err
	}

	log.Printf("[API] Successfully retrieved %d projects for hub %s", len(projects.Data), hubID)
	return &projects, err
}

func getProjectDetails(projectID string) (*Project, error) {
	log.Printf("[API] Fetching project details for project: %s", projectID)

	url := fmt.Sprintf("https://developer.api.autodesk.com/project/v1/projects/%s", projectID)
	resp, err := makeAuthorizedRequest(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[API] ERROR: Failed to read project details response: %v", err)
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("[API] ERROR: Get project details failed with HTTP %d: %s", resp.StatusCode, string(body))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	// Parse the response to get project data
	var result map[string]any
	err = json.Unmarshal(body, &result)
	if err != nil {
		log.Printf("[API] ERROR: Failed to parse project details response: %v", err)
		return nil, err
	}

	// Extract project data and convert back to Project struct
	projectData, ok := result["data"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid project details response format")
	}

	// Re-marshal and unmarshal to convert to Project struct
	projectBytes, err := json.Marshal(projectData)
	if err != nil {
		return nil, fmt.Errorf("failed to re-marshal project data: %v", err)
	}

	var project Project
	err = json.Unmarshal(projectBytes, &project)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal project: %v", err)
	}

	log.Printf("[API] Successfully retrieved project details: %s", project.Attributes.Name)
	return &project, nil
}

func getProjectDetailsWithHub(hubID, projectID string) (*Project, error) {
	log.Printf("[API] Fetching project details for project: %s in hub: %s", projectID, hubID)

	url := fmt.Sprintf("https://developer.api.autodesk.com/project/v1/hubs/%s/projects/%s", hubID, projectID)
	resp, err := makeAuthorizedRequest(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[API] ERROR: Failed to read project details response: %v", err)
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("[API] ERROR: Get project details failed with HTTP %d: %s", resp.StatusCode, string(body))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	// Parse the response to get project data
	var result map[string]any
	err = json.Unmarshal(body, &result)
	if err != nil {
		log.Printf("[API] ERROR: Failed to parse project details response: %v", err)
		return nil, err
	}

	// Extract project data and convert back to Project struct
	projectData, ok := result["data"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid project details response format")
	}

	// Re-marshal and unmarshal to convert to Project struct
	projectBytes, err := json.Marshal(projectData)
	if err != nil {
		return nil, fmt.Errorf("failed to re-marshal project data: %v", err)
	}

	var project Project
	err = json.Unmarshal(projectBytes, &project)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal project: %v", err)
	}

	log.Printf("[API] Successfully retrieved project details: %s", project.Attributes.Name)
	return &project, nil
}

func getProjectRootFolderDirect(projectID string) (string, error) {
	log.Printf("[API] Fetching root folder for project: %s", projectID)

	url := fmt.Sprintf("https://developer.api.autodesk.com/project/v1/projects/%s", projectID)
	resp, err := makeAuthorizedRequest(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	// Parse to get root folder ID from relationships
	var result map[string]any
	err = json.Unmarshal(body, &result)
	if err != nil {
		return "", err
	}

	data, ok := result["data"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("invalid response format")
	}

	relationships, ok := data["relationships"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("no relationships found")
	}

	rootFolder, ok := relationships["rootFolder"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("no rootFolder found")
	}

	folderData, ok := rootFolder["data"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("no folder data found")
	}

	folderID, ok := folderData["id"].(string)
	if !ok {
		return "", fmt.Errorf("no folder ID found")
	}

	log.Printf("[API] Successfully retrieved root folder ID: %s", folderID)
	return folderID, nil
}

func getProjectRootFolder(hubID, projectID string) (string, error) {
	url := fmt.Sprintf("https://developer.api.autodesk.com/project/v1/hubs/%s/projects/%s", hubID, projectID)
	resp, err := makeAuthorizedRequest(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	// Parse to get root folder ID from relationships
	var result map[string]any
	err = json.Unmarshal(body, &result)
	if err != nil {
		return "", err
	}

	data, ok := result["data"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("invalid response format")
	}

	relationships, ok := data["relationships"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("no relationships found")
	}

	rootFolder, ok := relationships["rootFolder"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("no rootFolder found")
	}

	folderData, ok := rootFolder["data"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("no folder data found")
	}

	folderID, ok := folderData["id"].(string)
	if !ok {
		return "", fmt.Errorf("no folder ID found")
	}

	return folderID, nil
}

func getFolderContents(projectID, folderID string) (*FolderContentsResponse, error) {
	log.Printf("[API] Fetching folder contents for project %s, folder %s", projectID, folderID)

	url := fmt.Sprintf("https://developer.api.autodesk.com/data/v1/projects/%s/folders/%s/contents", projectID, folderID)
	resp, err := makeAuthorizedRequest(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[API] ERROR: Failed to read folder contents response: %v", err)
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("[API] ERROR: Get folder contents failed with HTTP %d: %s", resp.StatusCode, string(body))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var contents FolderContentsResponse
	err = json.Unmarshal(body, &contents)
	if err != nil {
		log.Printf("[API] ERROR: Failed to parse folder contents response: %v", err)
		return nil, err
	}

	log.Printf("[API] Successfully retrieved %d items from folder", len(contents.Data))
	return &contents, err
}

func getItemVersions(projectID, itemID string) (*ItemVersionsResponse, error) {
	log.Printf("[API] Fetching versions for item %s in project %s", itemID, projectID)

	url := fmt.Sprintf("https://developer.api.autodesk.com/data/v1/projects/%s/items/%s/versions", projectID, itemID)
	resp, err := makeAuthorizedRequest(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[API] ERROR: Failed to read item versions response: %v", err)
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("[API] ERROR: Get item versions failed with HTTP %d: %s", resp.StatusCode, string(body))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var versions ItemVersionsResponse
	err = json.Unmarshal(body, &versions)
	if err != nil {
		log.Printf("[API] ERROR: Failed to parse item versions response: %v", err)
		return nil, err
	}

	log.Printf("[API] Successfully retrieved %d versions for item", len(versions.Data))
	return &versions, nil
}

// Get version details with storage relationships
func getVersionWithStorage(projectID, versionID string) (map[string]any, error) {
	log.Printf("[API] Getting version details with storage for version %s in project %s", versionID, projectID)

	// Use the versions endpoint to get detailed version info including storage
	encodedVersionID := url.QueryEscape(versionID)
	apiURL := fmt.Sprintf("https://developer.api.autodesk.com/data/v1/projects/%s/versions/%s", projectID, encodedVersionID)

	log.Printf("[API] Requesting version details: %s", apiURL)

	resp, err := makeAuthorizedRequest(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[API] ERROR: Failed to read version details response: %v", err)
		return nil, err
	}

	log.Printf("[API] Version details response (status %d): %s", resp.StatusCode, string(body))

	if resp.StatusCode != http.StatusOK {
		log.Printf("[API] ERROR: Get version details failed with HTTP %d: %s", resp.StatusCode, string(body))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var versionDetails map[string]any
	err = json.Unmarshal(body, &versionDetails)
	if err != nil {
		log.Printf("[API] ERROR: Failed to parse version details response: %v", err)
		return nil, err
	}

	log.Printf("[API] Successfully retrieved version details with storage")
	return versionDetails, nil
}

// Extract storage URN from version details response
func extractStorageURNFromVersion(versionDetails map[string]any) (string, error) {
	log.Printf("[API] Extracting storage URN from version details")

	// Navigate to data.relationships.storage.data.id
	data, ok := versionDetails["data"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("no data found in version details")
	}

	relationships, ok := data["relationships"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("no relationships found in version data")
	}

	storage, ok := relationships["storage"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("no storage found in relationships")
	}

	storageData, ok := storage["data"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("no storage data found")
	}

	storageID, ok := storageData["id"].(string)
	if !ok {
		return "", fmt.Errorf("no storage ID found")
	}

	log.Printf("[API] Successfully extracted storage URN: %s", storageID)
	return storageID, nil
}

// Parse bucket and object key from storage URN
func parseStorageURN(storageURN string) (string, string, error) {
	log.Printf("[API] Parsing storage URN: %s", storageURN)

	// Format: urn:adsk.objects:os.object:bucket/objectKey
	// Example: urn:adsk.objects:os.object:wip.dm.prod/d8ac29bd-23ae-46d8-9a6d-609a024acdc4.pdf

	parts := strings.Split(storageURN, ":")
	if len(parts) < 4 {
		return "", "", fmt.Errorf("invalid storage URN format: %s", storageURN)
	}

	bucketAndObject := parts[len(parts)-1] // Get the last part: bucket/objectKey
	pathParts := strings.SplitN(bucketAndObject, "/", 2)
	if len(pathParts) != 2 {
		return "", "", fmt.Errorf("invalid bucket/object format: %s", bucketAndObject)
	}

	bucket := pathParts[0]
	objectKey := pathParts[1]

	log.Printf("[API] Parsed URN - bucket: %s, objectKey: %s", bucket, objectKey)
	return bucket, objectKey, nil
}

// Get signed S3 download URL from OSS API
func getOSSSignedDownloadURL(bucket, objectKey string) (string, error) {
	log.Printf("[API] Getting signed S3 download URL for bucket: %s, objectKey: %s", bucket, objectKey)

	// Call OSS signeds3download endpoint
	encodedObjectKey := url.QueryEscape(objectKey)
	ossURL := fmt.Sprintf("https://developer.api.autodesk.com/oss/v2/buckets/%s/objects/%s/signeds3download", bucket, encodedObjectKey)

	log.Printf("[API] Requesting signed URL: %s", ossURL)

	resp, err := makeAuthorizedRequest(ossURL)
	if err != nil {
		return "", fmt.Errorf("failed to request signed URL: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read signed URL response: %v", err)
	}

	log.Printf("[API] Signed URL response (status %d): %s", resp.StatusCode, string(body))

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("signed URL request failed with HTTP %d: %s", resp.StatusCode, string(body))
	}

	var signedResponse map[string]any
	err = json.Unmarshal(body, &signedResponse)
	if err != nil {
		return "", fmt.Errorf("failed to parse signed URL response: %v", err)
	}

	downloadURL, ok := signedResponse["url"].(string)
	if !ok || downloadURL == "" {
		return "", fmt.Errorf("no download URL found in signed response")
	}

	log.Printf("[API] Successfully got signed S3 download URL")
	return downloadURL, nil
}

func streamFileDownload(w http.ResponseWriter, downloadURL, fileName string) error {
	log.Printf("[DOWNLOAD] Streaming file from URL: %s", downloadURL)

	// Make request to the download URL (this is typically a pre-signed URL from Autodesk)
	resp, err := http.Get(downloadURL)
	if err != nil {
		log.Printf("[DOWNLOAD] ERROR: Failed to fetch file: %v", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[DOWNLOAD] ERROR: Download failed with HTTP %d", resp.StatusCode)
		return fmt.Errorf("download failed with HTTP %d", resp.StatusCode)
	}

	// Set headers to force download
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", fileName))
	w.Header().Set("Content-Type", "application/octet-stream")

	// Copy content length if available
	if resp.ContentLength > 0 {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", resp.ContentLength))
	}

	// Stream the file content to the client
	log.Printf("[DOWNLOAD] Starting file stream...")
	bytesWritten, err := io.Copy(w, resp.Body)
	if err != nil {
		log.Printf("[DOWNLOAD] ERROR: Failed to stream file content: %v", err)
		return err
	}

	log.Printf("[DOWNLOAD] Successfully streamed %d bytes", bytesWritten)
	return nil
}

// Batch function to get custom attributes for multiple files at once
func getBatchCustomAttributes(projectID string, fileURNs []string) (map[string]any, error) {
	log.Printf("[API] Fetching batch custom attributes for %d files in project %s using BIM 360 Document Management API", len(fileURNs), projectID)

	if len(fileURNs) == 0 {
		return make(map[string]any), nil
	}

	cleanProjectID := projectID
	if strings.HasPrefix(projectID, "b.") {
		cleanProjectID = projectID[2:]
	}

	// Use BIM 360/ACC Document Management API - versions batch endpoint
	bimDocURL := fmt.Sprintf("https://developer.api.autodesk.com/bim360/docs/v1/projects/%s/versions:batch-get", cleanProjectID)
	log.Printf("[API] Making batch request to: %s", bimDocURL)
	log.Printf("[API] URNs to request: %v", fileURNs)

	// Create request body with all file URNs
	requestBody := map[string]any{
		"urns": fileURNs,
	}

	requestBodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		log.Printf("[API] ERROR: Failed to marshal batch request body: %v", err)
		return nil, err
	}

	log.Printf("[API] Request body: %s", string(requestBodyBytes))

	req, err := http.NewRequest("POST", bimDocURL, strings.NewReader(string(requestBodyBytes)))
	if err != nil {
		log.Printf("[API] ERROR: Failed to create batch request: %v", err)
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	bimResp, err := client.Do(req)
	if err != nil {
		log.Printf("[API] ERROR: Batch request failed: %v", err)
		return nil, err
	}
	defer bimResp.Body.Close()

	bimBody, err := io.ReadAll(bimResp.Body)
	if err != nil {
		log.Printf("[API] ERROR: Failed to read batch response: %v", err)
		return nil, err
	}

	log.Printf("[API] Batch response (status %d): %s", bimResp.StatusCode, string(bimBody))

	result := make(map[string]any)

	if bimResp.StatusCode == http.StatusOK {
		log.Printf("[API] SUCCESS: Batch custom attributes request successful!")
		var bimData any
		err = json.Unmarshal(bimBody, &bimData)
		if err != nil {
			log.Printf("[API] ERROR: Failed to parse batch response: %v", err)
			return nil, err
		}

		log.Printf("[API] Batch response data: %+v", bimData)

		// Parse the response to extract custom attributes for each file
		if dataMap, ok := bimData.(map[string]any); ok {
			if results, ok := dataMap["results"].([]any); ok {
				log.Printf("[API] Processing %d results from batch response", len(results))
				for i, resultItem := range results {
					if resultMap, ok := resultItem.(map[string]any); ok {
						// Extract URN/ID and custom attributes
						var urnID string
						if urn, exists := resultMap["urn"]; exists {
							urnID = fmt.Sprintf("%v", urn)
						}
						if urnID != "" && i < len(fileURNs) {
							urnID = fileURNs[i] // Use original URN from request
						}

						if customAttrs, exists := resultMap["customAttributes"]; exists {
							log.Printf("[API] Found custom attributes for URN %s: %+v", urnID, customAttrs)
							result[urnID] = customAttrs
						} else {
							log.Printf("[API] No customAttributes field found for URN %s", urnID)
							result[urnID] = "No custom attributes"
						}
					}
				}
			} else {
				log.Printf("[API] No 'results' array found in batch response")
			}
		}
	} else {
		log.Printf("[API] Batch request failed with HTTP %d: %s", bimResp.StatusCode, string(bimBody))
		return nil, fmt.Errorf("HTTP %d: %s", bimResp.StatusCode, string(bimBody))
	}

	log.Printf("[API] Returning %d custom attribute sets", len(result))
	return result, nil
}

// Format custom attributes from batch response
func formatCustomAttributesFromBatch(attrs any) string {
	if attrs == nil {
		return "No custom attributes"
	}

	// Handle string response
	if str, ok := attrs.(string); ok {
		return str
	}

	// Handle array of custom attributes
	if attrArray, ok := attrs.([]any); ok {
		if len(attrArray) == 0 {
			return "No custom attributes assigned"
		}

		var formattedAttrs []string
		for _, attr := range attrArray {
			if attrMap, ok := attr.(map[string]any); ok {
				name := "Unknown"
				value := "No value"

				if n, exists := attrMap["name"]; exists {
					name = fmt.Sprintf("%v", n)
				}
				if v, exists := attrMap["value"]; exists {
					value = fmt.Sprintf("%v", v)
				}

				formattedAttrs = append(formattedAttrs, fmt.Sprintf("%s: %s", name, value))
			}
		}

		if len(formattedAttrs) > 0 {
			return strings.Join(formattedAttrs, " | ")
		}
	}

	// Fallback: convert to JSON string
	jsonBytes, err := json.Marshal(attrs)
	if err != nil {
		return fmt.Sprintf("Error formatting: %v", err)
	}
	return string(jsonBytes)
}

func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// Token storage functions
func saveTokenToDisk(tokenResp *TokenResponse) error {
	stored := StoredToken{
		AccessToken: tokenResp.AccessToken,
		ExpiresAt:   time.Now().Unix() + int64(tokenResp.ExpiresIn),
	}

	log.Printf("[TOKEN] Saving token - expires at: %s", time.Unix(stored.ExpiresAt, 0).Format("2006-01-02 15:04:05 MST"))

	data, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal token: %v", err)
	}

	err = os.WriteFile("autodesk_token.json", data, 0600)
	if err != nil {
		return fmt.Errorf("failed to write token file: %v", err)
	}

	return nil
}

func loadTokenFromDisk() (*StoredToken, error) {
	data, err := os.ReadFile("autodesk_token.json")
	if err != nil {
		return nil, fmt.Errorf("failed to read token file: %v", err)
	}

	var stored StoredToken
	err = json.Unmarshal(data, &stored)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal token: %v", err)
	}

	return &stored, nil
}

func viewerHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[HANDLER] PDF viewer page requested from %s", r.RemoteAddr)

	projectID := r.URL.Query().Get("projectId")
	itemID := r.URL.Query().Get("itemId")
	versionNumber := r.URL.Query().Get("versionNumber")
	fileName := r.URL.Query().Get("fileName")

	if projectID == "" || itemID == "" {
		http.Error(w, "projectId and itemId parameters required", http.StatusBadRequest)
		return
	}

	// Build the download URL parameters
	downloadURLParams := fmt.Sprintf("projectId=%s&itemId=%s&fileName=%s",
		url.QueryEscape(projectID),
		url.QueryEscape(itemID),
		url.QueryEscape(fileName))

	if versionNumber != "" {
		downloadURLParams += fmt.Sprintf("&versionNumber=%s", url.QueryEscape(versionNumber))
	}

	downloadURL := fmt.Sprintf("/download?%s", downloadURLParams)

	// Prepare data for template
	data := struct {
		FileName    string
		DownloadURL string
	}{
		FileName:    fileName,
		DownloadURL: downloadURL,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "viewer.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func pdfProxyHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[PROXY] PDF proxy request from %s", r.RemoteAddr)

	// Handle preflight CORS requests
	if r.Method == "OPTIONS" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.WriteHeader(http.StatusOK)
		return
	}

	s3URL := r.URL.Query().Get("url")
	if s3URL == "" {
		log.Printf("[PROXY] ERROR: Missing URL parameter")
		http.Error(w, "Missing URL parameter", http.StatusBadRequest)
		return
	}

	log.Printf("[PROXY] Fetching PDF from S3: %s", s3URL[:100]+"...")

	// Create request to S3
	req, err := http.NewRequest("GET", s3URL, nil)
	if err != nil {
		log.Printf("[PROXY] ERROR: Failed to create S3 request: %v", err)
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Make the request with timeout
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[PROXY] ERROR: S3 request failed: %v", err)
		http.Error(w, "Failed to fetch PDF: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	log.Printf("[PROXY] S3 response status: %d", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		log.Printf("[PROXY] ERROR: S3 returned status %d", resp.StatusCode)
		http.Error(w, fmt.Sprintf("S3 returned status %d", resp.StatusCode), resp.StatusCode)
		return
	}

	// Set CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	// Set content headers
	w.Header().Set("Content-Type", "application/pdf")
	if contentLength := resp.Header.Get("Content-Length"); contentLength != "" {
		w.Header().Set("Content-Length", contentLength)
	}

	// Copy the PDF content
	bytesWritten, err := io.Copy(w, resp.Body)
	if err != nil {
		log.Printf("[PROXY] ERROR: Failed to copy PDF content: %v", err)
	} else {
		log.Printf("[PROXY] Successfully proxied %d bytes", bytesWritten)
	}
}
