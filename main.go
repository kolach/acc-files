package main

import (
	"encoding/json"
	"fmt"
	"github.com/joho/godotenv"
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
}

// OAuth token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// Stored token info for persistence
type StoredToken struct {
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
	ExpiresAt    int64  `json:"expires_at"` // Unix timestamp
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
	Type       string              `json:"type"`
	ID         string              `json:"id"`
	Attributes ItemDetailsAttribs  `json:"attributes"`
}

type ItemDetailsAttribs struct {
	Name         string                 `json:"name"`
	DisplayName  string                 `json:"displayName"`
	CreateTime   time.Time              `json:"createTime"`
	LastModified time.Time              `json:"lastModifiedTime"`
	Extension    ItemExtension          `json:"extension"`
}

type ItemExtension struct {
	Type string      `json:"type"`
	Version string   `json:"version"`
	Schema  interface{} `json:"schema"`
	Data    map[string]interface{} `json:"data"`
}

// Item versions response structure
type ItemVersionsResponse struct {
	Data []ItemVersion `json:"data"`
}

type ItemVersion struct {
	Type       string              `json:"type"`
	ID         string              `json:"id"`
	Attributes ItemVersionAttribs  `json:"attributes"`
}

type ItemVersionAttribs struct {
	Name            string    `json:"name"`
	DisplayName     string    `json:"displayName"`
	CreateTime      time.Time `json:"createTime"`
	LastModified    time.Time `json:"lastModifiedTime"`
	VersionNumber   int       `json:"versionNumber"`
	FileType        string    `json:"fileType"`
	StorageSize     int64     `json:"storageSize"`
}

// Version download info response structure  
type VersionDownloadResponse struct {
	JsonAPI       map[string]interface{} `json:"jsonapi"`
	Links         map[string]interface{} `json:"links"`
	Data          VersionDownloadData    `json:"data"`
	Relationships map[string]interface{} `json:"relationships"`
}

type VersionDownloadData struct {
	Type       string                     `json:"type"`
	ID         string                     `json:"id"`
	Attributes VersionDownloadAttributes  `json:"attributes"`
}

type VersionDownloadAttributes struct {
	Name        string                 `json:"name"`
	StorageSize int64                  `json:"storageSize"`
	Extension   VersionDownloadExt     `json:"extension"`
}

type VersionDownloadExt struct {
	Type string                    `json:"type"`
	Data map[string]interface{}    `json:"data"`
}

// Global variables
var (
	config Config
	token  *TokenResponse
)

func main() {
	log.Printf("[STARTUP] Starting Autodesk ACC File Lister application...")
	
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
	}

	if config.ClientID == "" || config.ClientSecret == "" {
		log.Fatal("[STARTUP] FATAL: Please set APS_CLIENT_ID and APS_CLIENT_SECRET environment variables")
	}

	log.Printf("[STARTUP] Configuration loaded:")
	log.Printf("[STARTUP] - Client ID: %s***", config.ClientID[:8])
	log.Printf("[STARTUP] - Redirect URI: %s", config.RedirectURI)
	log.Printf("[STARTUP] - Port: %s", config.Port)

	// Set up HTTP routes
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/callback", callbackHandler)
	http.HandleFunc("/projects", projectsHandler)
	http.HandleFunc("/files", filesHandler)
	http.HandleFunc("/test-token", testTokenHandler)
	http.HandleFunc("/token-status", tokenStatusHandler)
	http.HandleFunc("/versions", versionsHandler)
	http.HandleFunc("/download", downloadHandler)
	http.HandleFunc("/viewer", viewerHandler)
	http.HandleFunc("/pdf-proxy", pdfProxyHandler)

	log.Printf("[STARTUP] Routes configured:")
	log.Printf("[STARTUP] - / (home page)")
	log.Printf("[STARTUP] - /login (OAuth initiation)")
	log.Printf("[STARTUP] - /callback (OAuth callback)")
	log.Printf("[STARTUP] - /projects (project listing)")
	log.Printf("[STARTUP] - /files (file browser)")
	log.Printf("[STARTUP] - /test-token (test with custom token)")
	log.Printf("[STARTUP] - /token-status (check stored token status)")
	log.Printf("[STARTUP] - /versions (file versions)")
	log.Printf("[STARTUP] - /download (file download)")
	log.Printf("[STARTUP] - /viewer (PDF viewer)")
	log.Printf("[STARTUP] - /pdf-proxy (CORS proxy for S3)")

	// Try automatic authentication using stored refresh token
	if tryAutomaticAuthentication() {
		log.Printf("[STARTUP] ✅ Automatic authentication successful - ready for Fargate!")
		fmt.Printf("🔐 Already authenticated! You can access /projects directly\n")
	} else {
		log.Printf("[STARTUP] ⚠️  No stored authentication - manual login required")
		fmt.Printf("🔑 Visit /login to authenticate and save refresh token\n")
	}

	fmt.Printf("Server starting on port %s\n", config.Port)
	fmt.Printf("Visit: http://localhost:%s\n", config.Port)
	log.Printf("[STARTUP] Server ready and listening on port %s", config.Port)
	log.Fatal(http.ListenAndServe(":"+config.Port, nil))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	var authStatus, actions string
	
	if token != nil {
		authStatus = "✅ <strong>Authenticated</strong> - Ready for Fargate deployment!"
		actions = `
		<p><a href="/projects">View Your Projects</a></p>
		<p><a href="/test-token">🧪 Test DM v3 API with Custom Token</a></p>
		<p><em>Your refresh token is saved. This app can now run without user interaction.</em></p>`
	} else {
		authStatus = "❌ <strong>Not authenticated</strong> - Manual login required"
		actions = `
		<p><a href="/login">Login with Autodesk</a> (this will save your refresh token)</p>
		<p><a href="/test-token">🧪 Test DM v3 API with Custom Token</a></p>`
	}

	html := fmt.Sprintf(`
	<html>
	<head><title>Autodesk ACC File Lister - Refresh Token Version</title></head>
	<body>
		<h1>Autodesk ACC File Lister</h1>
		<p><strong>Status:</strong> %s</p>
		<hr>
		<h2>How it works:</h2>
		<ol>
			<li><strong>First time:</strong> Click "Login" → Authorize → Refresh token saved to <code>autodesk_token.json</code></li>
			<li><strong>Subsequent runs:</strong> App automatically uses saved refresh token (no user interaction needed)</li>
			<li><strong>Fargate ready:</strong> Deploy with the saved token file for autonomous operation</li>
		</ol>
		%s
		<hr>
		<p><small>Refresh tokens typically don't expire, but can be invalidated by password changes or app revocation.</small></p>
	</body>
	</html>`, authStatus, actions)
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, html)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[AUTH] Login initiated from %s", r.RemoteAddr)
	log.Printf("[AUTH] Client ID: %s", config.ClientID[:8]+"***")
	log.Printf("[AUTH] Redirect URI: %s", config.RedirectURI)
	log.Printf("[AUTH] Requested scopes: data:read account:read")
	
	// Generate authorization URL
	authURL := fmt.Sprintf(
		"https://developer.api.autodesk.com/authentication/v2/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=%s",
		url.QueryEscape(config.ClientID),
		url.QueryEscape(config.RedirectURI),
		url.QueryEscape("account:read account:write bucket:create bucket:read bucket:update bucket:delete data:read data:write data:create data:search user:read user:write user-profile:read viewables:read"),
	)

	log.Printf("[AUTH] Redirecting to Autodesk authorization server")
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[AUTH] OAuth callback received from %s", r.RemoteAddr)
	
	// Get authorization code from callback
	code := r.URL.Query().Get("code")
	if code == "" {
		log.Printf("[AUTH] ERROR: No authorization code received in callback")
		http.Error(w, "No authorization code received", http.StatusBadRequest)
		return
	}

	log.Printf("[AUTH] Authorization code received (length: %d)", len(code))
	log.Printf("[AUTH] Exchanging authorization code for access token...")

	// Exchange authorization code for access token
	var err error
	token, err = exchangeCodeForToken(code)
	if err != nil {
		log.Printf("[AUTH] ERROR: Failed to exchange code for token: %v", err)
		http.Error(w, fmt.Sprintf("Failed to exchange code for token: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[AUTH] SUCCESS: Access token obtained (expires in %d seconds)", token.ExpiresIn)
	log.Printf("[AUTH] Token type: %s", token.TokenType)
	if token.RefreshToken != "" {
		log.Printf("[AUTH] Refresh token also received - saving to disk")
		err = saveTokenToDisk(token)
		if err != nil {
			log.Printf("[AUTH] WARNING: Failed to save refresh token: %v", err)
		} else {
			log.Printf("[AUTH] Refresh token saved successfully for future use")
		}
	}

	// Success page
	html := `
	<html>
	<head><title>Authentication Success</title></head>
	<body>
		<h1>Authentication Successful!</h1>
		<p>You are now authenticated with Autodesk.</p>
		<p><a href="/projects">View Your Projects</a></p>
	</body>
	</html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, html)
}

func projectsHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[HANDLER] Projects page requested from %s", r.RemoteAddr)
	
	if token == nil {
		log.Printf("[HANDLER] ERROR: User not authenticated, redirecting to login")
		http.Error(w, "Not authenticated. Please login first.", http.StatusUnauthorized)
		return
	}

	log.Printf("[HANDLER] User is authenticated, fetching projects data")

	// Get hubs first
	hubs, err := getHubs()
	if err != nil {
		log.Printf("[HANDLER] ERROR: Failed to get hubs: %v", err)
		http.Error(w, fmt.Sprintf("Failed to get hubs: %v", err), http.StatusInternalServerError)
		return
	}

	html := `<html><head><title>Your Projects</title></head><body><h1>Your Hubs and Projects</h1>`

	for _, hub := range hubs.Data {
		html += fmt.Sprintf("<h2>Hub: %s</h2>", hub.Attributes.Name)

		// Get projects for this hub
		projects, err := getProjects(hub.ID)
		if err != nil {
			html += fmt.Sprintf("<p>Error getting projects: %v</p>", err)
			continue
		}

		html += "<ul>"
		for _, project := range projects.Data {
			html += fmt.Sprintf(
				`<li><a href="/files?hubId=%s&projectId=%s">%s</a> (ID: %s)</li>`,
				url.QueryEscape(hub.ID),
				url.QueryEscape(project.ID),
				project.Attributes.Name,
				project.ID,
			)
		}
		html += "</ul>"
	}

	html += "</body></html>"
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, html)
}

func tokenStatusHandler(w http.ResponseWriter, r *http.Request) {
	html := `<html><head><title>Token Status</title></head><body>
	<h1>Stored Token Status</h1>
	<p><a href="/">← Back to Home</a></p>`
	
	stored, err := loadTokenFromDisk()
	if err != nil {
		html += fmt.Sprintf(`<h2>❌ No Stored Token</h2><p>Error: %v</p>`, err)
	} else {
		now := time.Now().Unix()
		accessExpired := stored.ExpiresAt <= now
		
		html += fmt.Sprintf(`<h2>📊 Token Information</h2>
		<p><strong>Access Token:</strong> %s***</p>
		<p><strong>Refresh Token:</strong> %s***</p>
		<p><strong>Access Token Expires:</strong> %s</p>
		<p><strong>Access Token Status:</strong> %s</p>
		<p><strong>Time Until Expiry:</strong> %s</p>`,
			stored.AccessToken[:20],
			stored.RefreshToken[:20],
			time.Unix(stored.ExpiresAt, 0).Format("2006-01-02 15:04:05 MST"),
			func() string {
				if accessExpired {
					return "❌ EXPIRED"
				}
				return "✅ VALID"
			}(),
			func() string {
				diff := stored.ExpiresAt - now
				if diff <= 0 {
					return fmt.Sprintf("Expired %d seconds ago", -diff)
				}
				return fmt.Sprintf("%d seconds", diff)
			}())
		
		html += `<h2>🧪 Test Refresh Token</h2>
		<form method="POST">
			<input type="submit" name="action" value="Test Refresh Token">
		</form>`
	}
	
	if r.Method == "POST" && r.FormValue("action") == "Test Refresh Token" {
		stored, err := loadTokenFromDisk()
		if err != nil {
			html += fmt.Sprintf(`<h3>❌ Cannot test - no stored token</h3>`)
		} else {
			html += `<h3>🔄 Testing Refresh Token...</h3>`
			newToken, err := refreshAccessToken(stored.RefreshToken)
			if err != nil {
				html += fmt.Sprintf(`<p>❌ <strong>Refresh token INVALID or EXPIRED</strong></p>
				<p>Error: %v</p>
				<p>You need to re-authenticate via <a href="/login">/login</a></p>`, err)
			} else {
				html += fmt.Sprintf(`<p>✅ <strong>Refresh token is VALID</strong></p>
				<p>Successfully got new access token (expires in %d seconds)</p>
				<p>New access token: %s***</p>`, 
					newToken.ExpiresIn, newToken.AccessToken[:20])
			}
		}
	}
	
	html += `</body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, html)
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

	// Build HTML response
	html := fmt.Sprintf(`
	<html>
	<head><title>File Versions: %s</title>
	<style>
		table { border-collapse: collapse; width: 100%%; }
		th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
		th { background-color: #f2f2f2; }
		.version { background-color: white; }
		.latest { background-color: #e8f5e8; font-weight: bold; }
		.breadcrumb { margin: 10px 0; padding: 10px; background-color: #e9ecef; border-radius: 4px; }
		.file-info { background-color: #f8f9fa; padding: 10px; margin: 10px 0; border-radius: 4px; }
		.version a { text-decoration: none; color: #009900; font-weight: bold; }
		.version a:hover { text-decoration: underline; }
		.latest a { text-decoration: none; color: #006600; font-weight: bold; }
		.latest a:hover { text-decoration: underline; }
	</style>
	</head>
	<body>
		<h1>File Versions</h1>
		<div class="breadcrumb">
			<a href="javascript:history.back()">← Back to Files</a>
		</div>
		<div class="file-info">
			<strong>File:</strong> %s<br>
			<strong>Item ID:</strong> <small>%s</small><br>
			<strong>Total Versions:</strong> %d
		</div>
		<table>
			<tr>
				<th>Version</th>
				<th>Name</th>
				<th>File Type</th>
				<th>Size</th>
				<th>Created</th>
				<th>Last Modified</th>
				<th>Actions</th>
				<th>Version ID</th>
			</tr>
	`, fileName, fileName, itemID, len(versions.Data))

	// Sort versions by version number (descending - newest first)
	for i, version := range versions.Data {
		var rowClass string
		if i == 0 {
			rowClass = "latest" // Highlight latest version
		} else {
			rowClass = "version"
		}

		// Format file size
		sizeStr := "Unknown"
		if version.Attributes.StorageSize > 0 {
			if version.Attributes.StorageSize > 1024*1024 {
				sizeStr = fmt.Sprintf("%.2f MB", float64(version.Attributes.StorageSize)/(1024*1024))
			} else if version.Attributes.StorageSize > 1024 {
				sizeStr = fmt.Sprintf("%.2f KB", float64(version.Attributes.StorageSize)/1024)
			} else {
				sizeStr = fmt.Sprintf("%d bytes", version.Attributes.StorageSize)
			}
		}

		// Create download URL for this version using itemId instead of versionId
		downloadURL := fmt.Sprintf("/download?projectId=%s&itemId=%s&versionNumber=%d&fileName=%s",
			url.QueryEscape(projectID),
			url.QueryEscape(itemID),
			version.Attributes.VersionNumber,
			url.QueryEscape(version.Attributes.DisplayName))
		
		// Create viewer URL for PDF files
		viewerURL := fmt.Sprintf("/viewer?projectId=%s&itemId=%s&versionNumber=%d&fileName=%s",
			url.QueryEscape(projectID),
			url.QueryEscape(itemID),
			version.Attributes.VersionNumber,
			url.QueryEscape(version.Attributes.DisplayName))
		
		// Build actions cell based on file type
		var actionsCell string
		if strings.ToLower(version.Attributes.FileType) == "pdf" {
			actionsCell = fmt.Sprintf(`<a href="%s">👁️ View PDF</a> | <a href="%s" target="_blank">📥 Download</a>`, 
				viewerURL, downloadURL)
		} else {
			actionsCell = fmt.Sprintf(`<a href="%s" target="_blank">📥 Download</a>`, downloadURL)
		}

		html += fmt.Sprintf(
			`<tr class="%s">
				<td>%d%s</td>
				<td>📄 %s</td>
				<td>%s</td>
				<td>%s</td>
				<td>%s</td>
				<td>%s</td>
				<td>%s</td>
				<td><small>%s</small></td>
			</tr>`,
			rowClass,
			version.Attributes.VersionNumber,
			func() string { if i == 0 { return " (Latest)" } else { return "" } }(),
			version.Attributes.DisplayName,
			version.Attributes.FileType,
			sizeStr,
			version.Attributes.CreateTime.Format("2006-01-02 15:04:05"),
			version.Attributes.LastModified.Format("2006-01-02 15:04:05"),
			actionsCell,
			version.ID,
		)
	}

	html += "</table></body></html>"
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, html)
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

func testTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// Handle token test
		testToken := r.FormValue("token")
		projectID := r.FormValue("projectId")
		
		if testToken == "" || projectID == "" {
			http.Error(w, "Both token and project ID are required", http.StatusBadRequest)
			return
		}
		
		log.Printf("[TEST] Testing custom token for DM v3 API access...")
		log.Printf("[TEST] Project ID: %s", projectID)
		log.Printf("[TEST] Token: %s***", testToken[:20])
		
		// Temporarily replace the global token
		originalToken := token
		token = &TokenResponse{
			AccessToken: testToken,
			TokenType:   "Bearer",
		}
		
		// Test DM v3 API
		cleanProjectID := projectID
		if strings.HasPrefix(projectID, "b.") {
			cleanProjectID = projectID[2:]
		}
		
		dmv3URL := fmt.Sprintf("https://developer.api.autodesk.com/dm/v3/projects/%s/custom-attribute-definitions?offset=0&limit=1000&sort=-id", cleanProjectID)
		resp, err := makeAuthorizedRequest(dmv3URL)
		
		// Restore original token
		token = originalToken
		
		html := `<html><head><title>Token Test Results</title></head><body>
		<h1>DM v3 API Test Results</h1>
		<p><a href="/test-token">← Back to Test Form</a></p>`
		
		if err != nil {
			html += fmt.Sprintf(`<h2>❌ Request Failed</h2><p>Error: %v</p>`, err)
		} else {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			
			html += fmt.Sprintf(`<h2>Response Status: %d</h2>`, resp.StatusCode)
			
			if resp.StatusCode == 200 {
				html += `<h3>✅ SUCCESS! DM v3 API is accessible with your token</h3>`
			} else if resp.StatusCode == 403 {
				html += `<h3>❌ 403 Forbidden - Your account may not have DM v3 access either</h3>`
			} else {
				html += fmt.Sprintf(`<h3>❌ HTTP %d</h3>`, resp.StatusCode)
			}
			
			html += fmt.Sprintf(`<h3>Raw Response:</h3><pre>%s</pre>`, string(body))
		}
		
		html += `</body></html>`
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, html)
		return
	}
	
	// Show the form
	html := `
	<html>
	<head><title>Test Custom Token</title></head>
	<body>
		<h1>Test DM v3 API with Your Browser Token</h1>
		<p><a href="/">← Back to Home</a></p>
		
		<h2>Instructions:</h2>
		<ol>
			<li>Open ACC in your browser and login</li>
			<li>Open Developer Tools (F12)</li>
			<li>Go to Network tab</li>
			<li>Look for requests to developer.api.autodesk.com</li>
			<li>Find the Authorization header: "Bearer eyJ0eXAi..."</li>
			<li>Copy the token part (after "Bearer ")</li>
			<li>Also find your project ID from the URL or API calls</li>
		</ol>
		
		<form method="POST">
			<h3>Test Token:</h3>
			<p><label>Token (without "Bearer "):</label><br>
			<input type="text" name="token" size="80" placeholder="eyJ0eXAiOiJKV1QiLCJhbGci..." required></p>
			
			<p><label>Project ID:</label><br>
			<input type="text" name="projectId" size="40" placeholder="b.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" required></p>
			
			<p><input type="submit" value="Test DM v3 API Access"></p>
		</form>
		
		<h2>Next Steps:</h2>
		<p>If the test above succeeds, you can use your token in the file browser:</p>
		<ol>
			<li>Go to <a href="/projects">Projects</a> and navigate to a project</li>
			<li>Add <code>?token=YOUR_TOKEN</code> to the file browser URL</li>
			<li>Example: <code>/files?hubId=...&projectId=...&token=YOUR_TOKEN</code></li>
		</ol>
		
		<h2>Alternative: Use cURL directly</h2>
		<p>You can also test this directly with cURL:</p>
		<pre>curl -H "Authorization: Bearer YOUR_TOKEN" \
  "https://developer.api.autodesk.com/dm/v3/projects/YOUR_PROJECT_ID/custom-attribute-definitions?offset=0&limit=1000&sort=-id"</pre>
	</body>
	</html>`
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, html)
}

func filesHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[HANDLER] Files page requested from %s", r.RemoteAddr)
	
	if token == nil {
		log.Printf("[HANDLER] ERROR: User not authenticated, redirecting to login")
		http.Error(w, "Not authenticated. Please login first.", http.StatusUnauthorized)
		return
	}

	hubID := r.URL.Query().Get("hubId")
	projectID := r.URL.Query().Get("projectId")
	folderID := r.URL.Query().Get("folderId")

	if hubID == "" || projectID == "" {
		log.Printf("[HANDLER] ERROR: Missing required parameters - hubId: %s, projectId: %s", hubID, projectID)
		http.Error(w, "hubId and projectId parameters required", http.StatusBadRequest)
		return
	}

	var targetFolderID string
	var err error

	if folderID != "" {
		log.Printf("[HANDLER] Navigating to specific folder: %s in project %s", folderID, projectID)
		targetFolderID = folderID
	} else {
		log.Printf("[HANDLER] Getting root folder for project %s in hub %s", projectID, hubID)
		// Get project root folder
		targetFolderID, err = getProjectRootFolder(hubID, projectID)
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
	var fileItems []FolderItem
	
	for _, item := range contents.Data {
		if item.Type != "folders" {
			fileURNs = append(fileURNs, item.ID)
			fileItems = append(fileItems, item)
			log.Printf("[HANDLER] Found file URN: %s (%s)", item.ID, item.Attributes.DisplayName)
		}
	}
	
	log.Printf("[HANDLER] Collected %d file URNs for batch custom attributes lookup", len(fileURNs))
	
	// Get custom attributes for all files in one batch request
	var batchCustomAttributes map[string]interface{}
	if len(fileURNs) > 0 {
		batchCustomAttributes, err = getBatchCustomAttributes(projectID, fileURNs)
		if err != nil {
			log.Printf("[HANDLER] WARNING: Batch custom attributes request failed: %v", err)
			batchCustomAttributes = make(map[string]interface{})
		}
	}

	// Build navigation breadcrumb
	var breadcrumb string
	if folderID == "" {
		breadcrumb = "📁 Project Root"
	} else {
		breadcrumb = fmt.Sprintf(`📁 <a href="/files?hubId=%s&projectId=%s">Project Root</a> / Current Folder`, 
			url.QueryEscape(hubID), url.QueryEscape(projectID))
	}

	// Display files
	html := fmt.Sprintf(`
	<html>
	<head><title>Project Files with Custom Attributes</title>
	<style>
		table { border-collapse: collapse; width: 100%%; }
		th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
		th { background-color: #f2f2f2; }
		.folder { background-color: #f9f9f9; }
		.folder a { text-decoration: none; color: #0066cc; font-weight: bold; }
		.folder a:hover { text-decoration: underline; }
		.file { background-color: white; }
		.file a { text-decoration: none; color: #009900; font-weight: bold; }
		.file a:hover { text-decoration: underline; }
		.breadcrumb { margin: 10px 0; padding: 10px; background-color: #e9ecef; border-radius: 4px; }
		.success { color: green; font-weight: bold; }
		.error { color: red; font-style: italic; }
	</style>
	</head>
	<body>
		<h1>Files in Project (with Batch Custom Attributes)</h1>
		<p><a href="/projects">← Back to Projects</a></p>
		<div class="breadcrumb">%s</div>
		<p><strong>Debug Info:</strong> Found %d files, retrieved batch attributes: %v</p>
		<table>
			<tr>
				<th>Name</th>
				<th>Type</th>
				<th>URN</th>
				<th>Last Modified</th>
				<th>Custom Attributes</th>
			</tr>
	`, breadcrumb, len(fileURNs), len(batchCustomAttributes) > 0)

	for _, item := range contents.Data {
		var nameCell, rowClass, attributesCell string
		
		if item.Type == "folders" {
			// Make folders clickable
			folderURL := fmt.Sprintf("/files?hubId=%s&projectId=%s&folderId=%s",
				url.QueryEscape(hubID),
				url.QueryEscape(projectID),
				url.QueryEscape(item.ID))
			
			nameCell = fmt.Sprintf(`<a href="%s">📁 %s</a>`, folderURL, item.Attributes.DisplayName)
			rowClass = "folder"
			attributesCell = "<em>N/A for folders</em>"
		} else {
			// Regular files - make them clickable to view versions
			versionsURL := fmt.Sprintf("/versions?projectId=%s&itemId=%s&fileName=%s",
				url.QueryEscape(projectID),
				url.QueryEscape(item.ID),
				url.QueryEscape(item.Attributes.DisplayName))
			
			nameCell = fmt.Sprintf(`<a href="%s">📄 %s</a>`, versionsURL, item.Attributes.DisplayName)
			rowClass = "file"
			
			// Check if we have custom attributes for this file from batch request
			if fileAttrs, exists := batchCustomAttributes[item.ID]; exists {
				log.Printf("[HANDLER] SUCCESS: Found batch custom attributes for %s", item.Attributes.DisplayName)
				attributesCell = fmt.Sprintf(`<span class="success">%s</span>`, formatCustomAttributesFromBatch(fileAttrs))
			} else {
				log.Printf("[HANDLER] No custom attributes found in batch for %s", item.Attributes.DisplayName)
				attributesCell = `<span class="error">No custom attributes in batch response</span>`
			}
		}

		html += fmt.Sprintf(
			`<tr class="%s"><td>%s</td><td>%s</td><td><small>%s</small></td><td>%s</td><td>%s</td></tr>`,
			rowClass,
			nameCell,
			item.Type,
			item.ID,
			item.Attributes.LastModified.Format("2006-01-02 15:04:05"),
			attributesCell,
		)
	}

	html += "</table></body></html>"
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, html)
}

func exchangeCodeForToken(code string) (*TokenResponse, error) {
	log.Printf("[AUTH] Preparing token exchange request to Autodesk")
	
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", config.ClientID)
	data.Set("client_secret", config.ClientSecret)
	data.Set("redirect_uri", config.RedirectURI)

	log.Printf("[AUTH] Making POST request to token endpoint")
	req, err := http.NewRequest("POST", "https://developer.api.autodesk.com/authentication/v2/token", strings.NewReader(data.Encode()))
	if err != nil {
		log.Printf("[AUTH] ERROR: Failed to create token request: %v", err)
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

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
		log.Printf("[AUTH] ERROR: Token exchange failed with HTTP %d: %s", resp.StatusCode, string(body))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	err = json.Unmarshal(body, &tokenResp)
	if err != nil {
		log.Printf("[AUTH] ERROR: Failed to parse token response: %v", err)
		return nil, err
	}

	log.Printf("[AUTH] Token exchange successful")
	return &tokenResp, nil
}

func makeAuthorizedRequest(url string) (*http.Response, error) {
	log.Printf("[API] Making authorized request to: %s", url)
	
	// Try request with current token first
	resp, err := doAuthorizedRequest(url)
	if err != nil {
		return nil, err
	}
	
	// If we get 401 (token expired), try refreshing and retry once
	if resp.StatusCode == 401 {
		log.Printf("[API] Access token expired (401), attempting to refresh...")
		resp.Body.Close() // Close the 401 response
		
		// Load stored token and refresh
		stored, err := loadTokenFromDisk()
		if err != nil {
			log.Printf("[API] ERROR: Cannot load stored token for refresh: %v", err)
			return resp, nil // Return original 401 response
		}
		
		newToken, err := refreshAccessToken(stored.RefreshToken)
		if err != nil {
			log.Printf("[API] ERROR: Failed to refresh access token: %v", err)
			return resp, nil // Return original 401 response
		}
		
		// Update global token
		token = newToken
		log.Printf("[API] Successfully refreshed token, retrying request...")
		
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
	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return "", err
	}

	data, ok := result["data"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid response format")
	}

	relationships, ok := data["relationships"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("no relationships found")
	}

	rootFolder, ok := relationships["rootFolder"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("no rootFolder found")
	}

	folderData, ok := rootFolder["data"].(map[string]interface{})
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
func getVersionWithStorage(projectID, versionID string) (map[string]interface{}, error) {
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

	var versionDetails map[string]interface{}
	err = json.Unmarshal(body, &versionDetails)
	if err != nil {
		log.Printf("[API] ERROR: Failed to parse version details response: %v", err)
		return nil, err
	}
	
	log.Printf("[API] Successfully retrieved version details with storage")
	return versionDetails, nil
}

// Extract storage URN from version details response
func extractStorageURNFromVersion(versionDetails map[string]interface{}) (string, error) {
	log.Printf("[API] Extracting storage URN from version details")
	
	// Navigate to data.relationships.storage.data.id
	data, ok := versionDetails["data"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("no data found in version details")
	}

	relationships, ok := data["relationships"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("no relationships found in version data")
	}

	storage, ok := relationships["storage"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("no storage found in relationships")
	}

	storageData, ok := storage["data"].(map[string]interface{})
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

	var signedResponse map[string]interface{}
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

func getVersionDownloadInfo(projectID, itemID string) (*VersionDownloadResponse, error) {
	log.Printf("[API] Getting download info for item %s in project %s using items endpoint", itemID, projectID)
	
	// Use the items endpoint as shown in the documentation
	encodedItemID := url.QueryEscape(itemID)
	apiURL := fmt.Sprintf("https://developer.api.autodesk.com/data/v1/projects/%s/items/%s", projectID, encodedItemID)
	
	log.Printf("[API] Trying items endpoint: %s", apiURL)
	
	resp, err := makeAuthorizedRequest(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[API] ERROR: Failed to read items response: %v", err)
		return nil, err
	}

	log.Printf("[API] Items response (status %d): %s", resp.StatusCode, string(body))

	if resp.StatusCode != http.StatusOK {
		log.Printf("[API] ERROR: Get items info failed with HTTP %d: %s", resp.StatusCode, string(body))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	// Parse as raw JSON first to check for included versions with storage info
	var rawResponse map[string]interface{}
	err = json.Unmarshal(body, &rawResponse)
	if err != nil {
		log.Printf("[API] ERROR: Failed to parse items response as raw JSON: %v", err)
		return nil, err
	}
	
	// Check for included array which might contain version information with storage
	if included, ok := rawResponse["included"].([]interface{}); ok && len(included) > 0 {
		log.Printf("[API] Found %d included items, checking for version with storage", len(included))
		
		// Look for a version item in the included array that has storage relationships
		for i, item := range included {
			if itemMap, ok := item.(map[string]interface{}); ok {
				if itemType, ok := itemMap["type"].(string); ok {
					log.Printf("[API] Included item %d: type=%s", i, itemType)
					
					// Look for versions type items
					if strings.Contains(itemType, "version") {
						log.Printf("[API] Found version item in included: %s", itemType)
						
						// Check if this version has relationships with storage
						if relationships, ok := itemMap["relationships"].(map[string]interface{}); ok {
							log.Printf("[API] Version has relationships: %v", getMapKeys(relationships))
							
							if storage, ok := relationships["storage"].(map[string]interface{}); ok {
								log.Printf("[API] Found storage relationship in included version: %v", getMapKeys(storage))
								
								// Convert this to our expected format - use the entire itemMap as the response
								downloadInfo := VersionDownloadResponse{
									Relationships: relationships,
								}
								
								// Parse the version item's data correctly
								downloadInfo.Data.Type = itemType
								if id, ok := itemMap["id"].(string); ok {
									downloadInfo.Data.ID = id
								}
								
								// Parse attributes if available
								if attributes, ok := itemMap["attributes"].(map[string]interface{}); ok {
									if name, ok := attributes["name"].(string); ok {
										downloadInfo.Data.Attributes.Name = name
									}
									if storageSize, ok := attributes["storageSize"].(float64); ok {
										downloadInfo.Data.Attributes.StorageSize = int64(storageSize)
									}
								}
								
								log.Printf("[API] Successfully found storage info in included version")
								return &downloadInfo, nil
							}
						} else {
							log.Printf("[API] Version item %d has no relationships", i)
						}
					}
				}
			}
		}
		
		log.Printf("[API] No version items with storage found in included array")
	} else {
		log.Printf("[API] No included array found in items response")
	}

	// Fallback: parse as standard response
	var downloadInfo VersionDownloadResponse
	err = json.Unmarshal(body, &downloadInfo)
	if err != nil {
		log.Printf("[API] ERROR: Failed to parse items response: %v", err)
		return nil, err
	}
	
	log.Printf("[API] Parsed relationships: %d items", len(downloadInfo.Relationships))
	
	log.Printf("[API] Successfully retrieved download info from items endpoint")
	return &downloadInfo, nil
}

func getVersionDownloadInfoFromURL(apiURL string) (*VersionDownloadResponse, error) {
	log.Printf("[API] Trying download info URL: %s", apiURL)
	
	resp, err := makeAuthorizedRequest(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[API] ERROR: Failed to read download info response: %v", err)
		return nil, err
	}

	log.Printf("[API] Download info response (status %d): %s", resp.StatusCode, string(body))

	if resp.StatusCode != http.StatusOK {
		log.Printf("[API] ERROR: Get download info failed with HTTP %d: %s", resp.StatusCode, string(body))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var downloadInfo VersionDownloadResponse
	err = json.Unmarshal(body, &downloadInfo)
	if err != nil {
		log.Printf("[API] ERROR: Failed to parse download info response: %v", err)
		return nil, err
	}
	
	log.Printf("[API] Parsed relationships: %d items", len(downloadInfo.Relationships))
	
	log.Printf("[API] Successfully retrieved download info for version")
	return &downloadInfo, nil
}

func getVersionDownloadInfoAlternative(projectID, versionID string) (*VersionDownloadResponse, error) {
	log.Printf("[API] Trying alternative download endpoint for version %s", versionID)
	
	// Try the downloadable endpoint which might work better
	encodedVersionID := url.QueryEscape(versionID)
	apiURL := fmt.Sprintf("https://developer.api.autodesk.com/data/v1/projects/%s/versions/%s/downloadable", projectID, encodedVersionID)
	
	log.Printf("[API] Alternative download URL: %s", apiURL)
	
	resp, err := makeAuthorizedRequest(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[API] ERROR: Failed to read alternative download response: %v", err)
		return nil, err
	}

	log.Printf("[API] Alternative download response (status %d): %s", resp.StatusCode, string(body))

	if resp.StatusCode != http.StatusOK {
		log.Printf("[API] ERROR: Alternative download failed with HTTP %d: %s", resp.StatusCode, string(body))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var downloadInfo VersionDownloadResponse
	err = json.Unmarshal(body, &downloadInfo)
	if err != nil {
		log.Printf("[API] ERROR: Failed to parse alternative download response: %v", err)
		return nil, err
	}
	
	log.Printf("[API] Parsed alternative relationships: %d items", len(downloadInfo.Relationships))
	
	log.Printf("[API] Successfully retrieved download info from alternative endpoint")
	return &downloadInfo, nil
}

// Helper function to get map keys for debugging
func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func getSignedS3DownloadURL(projectID, itemID string) (string, error) {
	log.Printf("[API] Getting signed S3 download URL for item %s using correct ACC process", itemID)
	
	// Step 1: Parse raw JSON to extract storage information directly
	encodedItemID := url.QueryEscape(itemID)
	apiURL := fmt.Sprintf("https://developer.api.autodesk.com/data/v1/projects/%s/items/%s", projectID, encodedItemID)
	
	resp, err := makeAuthorizedRequest(apiURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var rawResponse map[string]interface{}
	err = json.Unmarshal(body, &rawResponse)
	if err != nil {
		return "", err
	}
	
	// Check if this is a BIM 360/ACC file based on the extension type
	data, ok := rawResponse["data"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("no data found in version response")
	}
	
	attributes, ok := data["attributes"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("no attributes found in version response")
	}
	
	extension, ok := attributes["extension"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("no extension found in version response")
	}
	
	extensionType, ok := extension["type"].(string)
	if !ok {
		return "", fmt.Errorf("no extension type found")
	}
	
	log.Printf("[API] Extension type: %s", extensionType)
	
	// For BIM 360/ACC files (detected by extension type), use specialized endpoints
	if strings.Contains(extensionType, "bim360") {
		log.Printf("[API] Detected BIM 360/ACC file, trying BIM 360 specific download methods")
		
		// Extract project ID without "b." prefix for BIM 360 APIs
		cleanProjectID := projectID
		if strings.HasPrefix(projectID, "b.") {
			cleanProjectID = projectID[2:]
		}
		
		// Method 1: Try BIM 360 Document Management API download endpoint
		bimDownloadURL := fmt.Sprintf("https://developer.api.autodesk.com/bim360/docs/v1/projects/%s/versions/%s/downloads", cleanProjectID, url.QueryEscape(itemID))
		log.Printf("[API] Trying BIM 360 downloads endpoint: %s", bimDownloadURL)
		
		bimResp, err := makeAuthorizedRequest(bimDownloadURL)
		if err == nil {
			defer bimResp.Body.Close()
			bimBody, err := io.ReadAll(bimResp.Body)
			if err == nil {
				log.Printf("[API] BIM 360 downloads response (status %d): %s", bimResp.StatusCode, string(bimBody))
				
				if bimResp.StatusCode == 200 {
					var bimResponse map[string]interface{}
					if json.Unmarshal(bimBody, &bimResponse) == nil {
						// Check for download URL in various possible locations
						if downloadURL, ok := bimResponse["url"].(string); ok && downloadURL != "" {
							log.Printf("[API] Successfully got download URL from BIM 360 downloads")
							return downloadURL, nil
						}
						if formats, ok := bimResponse["formats"].([]interface{}); ok && len(formats) > 0 {
							if format, ok := formats[0].(map[string]interface{}); ok {
								if downloadURL, ok := format["downloadUrl"].(string); ok && downloadURL != "" {
									log.Printf("[API] Successfully got download URL from BIM 360 formats")
									return downloadURL, nil
								}
							}
						}
					}
				}
			}
		}
		
		// Method 2: Try Construction Docs API download endpoint  
		docsDownloadURL := fmt.Sprintf("https://developer.api.autodesk.com/construction/docs/v1/projects/%s/versions/%s/downloads", cleanProjectID, url.QueryEscape(itemID))
		log.Printf("[API] Trying Construction Docs downloads endpoint: %s", docsDownloadURL)
		
		docsResp, err := makeAuthorizedRequest(docsDownloadURL)
		if err == nil {
			defer docsResp.Body.Close()
			docsBody, err := io.ReadAll(docsResp.Body)
			if err == nil {
				log.Printf("[API] Construction Docs downloads response (status %d): %s", docsResp.StatusCode, string(docsBody))
				
				if docsResp.StatusCode == 200 {
					var docsResponse map[string]interface{}
					if json.Unmarshal(docsBody, &docsResponse) == nil {
						if downloadURL, ok := docsResponse["url"].(string); ok && downloadURL != "" {
							log.Printf("[API] Successfully got download URL from Construction Docs")
							return downloadURL, nil
						}
						if downloadURL, ok := docsResponse["downloadUrl"].(string); ok && downloadURL != "" {
							log.Printf("[API] Successfully got downloadUrl from Construction Docs")
							return downloadURL, nil
						}
					}
				}
			}
		}
	}
	
	// Method 3: Try the standard APS Data Management API downloads endpoint
	log.Printf("[API] Trying standard APS Data Management API downloads endpoint")
	downloadsURL := fmt.Sprintf("https://developer.api.autodesk.com/data/v1/projects/%s/versions/%s/downloads", projectID, url.QueryEscape(itemID))
	log.Printf("[API] Requesting downloads from APS endpoint: %s", downloadsURL)
	
	downloadsResp, err := makeAuthorizedRequest(downloadsURL)
	if err == nil {
		defer downloadsResp.Body.Close()
		downloadsBody, err := io.ReadAll(downloadsResp.Body)
		if err == nil {
			log.Printf("[API] APS downloads response (status %d): %s", downloadsResp.StatusCode, string(downloadsBody))
			
			if downloadsResp.StatusCode == 200 {
				var downloadsResponse map[string]interface{}
				if json.Unmarshal(downloadsBody, &downloadsResponse) == nil {
					if downloadURL, ok := downloadsResponse["url"].(string); ok && downloadURL != "" {
						log.Printf("[API] Successfully got download URL from APS downloads")
						return downloadURL, nil
					}
				}
			}
		}
	}
	
	log.Printf("[API] All download methods failed, attempting fallback approach...")
	
	// For regular Data Management API files, extract storage information from relationships
	relationships, ok := rawResponse["relationships"].(map[string]interface{})
	if !ok {
		log.Printf("[API] DEBUG: rawResponse keys: %v", getMapKeys(rawResponse))
		if rawResponse["relationships"] == nil {
			return "", fmt.Errorf("relationships is null in version response - this may be a BIM 360 file that needs different API")
		}
		return "", fmt.Errorf("no relationships found in version response (type: %T)", rawResponse["relationships"])
	}
	
	log.Printf("[API] Found relationships with keys: %v", getMapKeys(relationships))
	
	storage, ok := relationships["storage"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("no storage found in relationships")
	}
	
	storageData, ok := storage["data"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("no storage data found")
	}
	
	storageID, ok := storageData["id"].(string)
	if !ok {
		return "", fmt.Errorf("no storage ID found")
	}
	
	log.Printf("[API] Found storage ID: %s", storageID)
	
	// Parse bucket and object key from URN
	// Format: urn:adsk.objects:os.object:bucket/objectKey
	parts := strings.Split(storageID, ":")
	if len(parts) < 4 {
		return "", fmt.Errorf("invalid storage ID format: %s", storageID)
	}
	
	bucketAndObject := parts[len(parts)-1]
	pathParts := strings.SplitN(bucketAndObject, "/", 2)
	if len(pathParts) != 2 {
		return "", fmt.Errorf("invalid bucket/object format: %s", bucketAndObject)
	}
	
	bucket := pathParts[0]
	objectKey := pathParts[1]
	
	log.Printf("[API] Parsed bucket: %s, objectKey: %s", bucket, objectKey)
	
	// Generate signed S3 download URL using OSS API
	signedURL := fmt.Sprintf("https://developer.api.autodesk.com/oss/v2/buckets/%s/objects/%s/signeds3download", bucket, url.QueryEscape(objectKey))
	log.Printf("[API] Requesting signed URL: %s", signedURL)
	
	signedResp, err := makeAuthorizedRequest(signedURL)
	if err != nil {
		return "", fmt.Errorf("failed to get signed URL: %v", err)
	}
	defer signedResp.Body.Close()
	
	signedBody, err := io.ReadAll(signedResp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read signed URL response: %v", err)
	}
	
	log.Printf("[API] Signed URL response (status %d): %s", signedResp.StatusCode, string(signedBody))
	
	if signedResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("signed URL request failed with HTTP %d: %s", signedResp.StatusCode, string(signedBody))
	}
	
	var signedResponse map[string]interface{}
	err = json.Unmarshal(signedBody, &signedResponse)
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
func getBatchCustomAttributes(projectID string, fileURNs []string) (map[string]interface{}, error) {
	log.Printf("[API] Fetching batch custom attributes for %d files in project %s using BIM 360 Document Management API", len(fileURNs), projectID)
	
	if len(fileURNs) == 0 {
		return make(map[string]interface{}), nil
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
	requestBody := map[string]interface{}{
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
	
	result := make(map[string]interface{})
	
	if bimResp.StatusCode == http.StatusOK {
		log.Printf("[API] SUCCESS: Batch custom attributes request successful!")
		var bimData interface{}
		err = json.Unmarshal(bimBody, &bimData)
		if err != nil {
			log.Printf("[API] ERROR: Failed to parse batch response: %v", err)
			return nil, err
		}
		
		log.Printf("[API] Batch response data: %+v", bimData)
		
		// Parse the response to extract custom attributes for each file
		if dataMap, ok := bimData.(map[string]interface{}); ok {
			if results, ok := dataMap["results"].([]interface{}); ok {
				log.Printf("[API] Processing %d results from batch response", len(results))
				for i, resultItem := range results {
					if resultMap, ok := resultItem.(map[string]interface{}); ok {
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
func formatCustomAttributesFromBatch(attrs interface{}) string {
	if attrs == nil {
		return "<em>No custom attributes</em>"
	}
	
	// Handle string response
	if str, ok := attrs.(string); ok {
		return fmt.Sprintf("<em>%s</em>", str)
	}
	
	// Handle array of custom attributes
	if attrArray, ok := attrs.([]interface{}); ok {
		if len(attrArray) == 0 {
			return "<em>No custom attributes assigned</em>"
		}
		
		var formattedAttrs []string
		for _, attr := range attrArray {
			if attrMap, ok := attr.(map[string]interface{}); ok {
				name := "Unknown"
				value := "No value"
				
				if n, exists := attrMap["name"]; exists {
					name = fmt.Sprintf("%v", n)
				}
				if v, exists := attrMap["value"]; exists {
					value = fmt.Sprintf("%v", v)
				}
				
				formattedAttrs = append(formattedAttrs, fmt.Sprintf("<strong>%s:</strong> %s", name, value))
			}
		}
		
		if len(formattedAttrs) > 0 {
			return strings.Join(formattedAttrs, "<br>")
		}
	}
	
	// Fallback: convert to JSON string
	jsonBytes, err := json.Marshal(attrs)
	if err != nil {
		return fmt.Sprintf("<em>Error formatting: %v</em>", err)
	}
	return fmt.Sprintf("<pre>%s</pre>", string(jsonBytes))
}

// New function to get custom attribute values for a specific file
func getCustomAttributeValues(projectID, itemID string) (map[string]interface{}, error) {
	log.Printf("[API] Fetching custom attribute values for item %s in project %s using ACC Document Management API", itemID, projectID)
	
	customAttrs := make(map[string]interface{})
	
	cleanProjectID := projectID
	if strings.HasPrefix(projectID, "b.") {
		cleanProjectID = projectID[2:]
	}
	
	// Try BIM 360/ACC Document Management API - versions batch endpoint
	// This endpoint can return custom attributes for items
	bimDocURL := fmt.Sprintf("https://developer.api.autodesk.com/bim360/docs/v1/projects/%s/versions:batch-get", cleanProjectID)
	log.Printf("[API] Trying BIM 360 Document Management API versions batch endpoint: %s", bimDocURL)
	
	// Create request body to get version info for our item
	// Use the item ID as lineage URN format
	requestBody := map[string]interface{}{
		"urns": []string{itemID},
	}
	
	requestBodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		log.Printf("[API] ERROR: Failed to marshal request body: %v", err)
		return customAttrs, err
	}
	
	req, err := http.NewRequest("POST", bimDocURL, strings.NewReader(string(requestBodyBytes)))
	if err != nil {
		log.Printf("[API] ERROR: Failed to create ACC Document Management request: %v", err)
		return customAttrs, err
	}
	
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{}
	bimResp, err := client.Do(req)
	if err != nil {
		log.Printf("[API] ERROR: BIM 360 Document Management request failed: %v", err)
		return customAttrs, err
	}
	defer bimResp.Body.Close()
	
	bimBody, err := io.ReadAll(bimResp.Body)
	if err != nil {
		log.Printf("[API] ERROR: Failed to read BIM 360 Document Management response: %v", err)
		return customAttrs, err
	}
	
	log.Printf("[API] BIM 360 Document Management response (status %d): %s", bimResp.StatusCode, string(bimBody))
	
	if bimResp.StatusCode == http.StatusOK {
		log.Printf("[API] SUCCESS: BIM 360 Document Management API accessible!")
		var bimData interface{}
		err = json.Unmarshal(bimBody, &bimData)
		if err != nil {
			log.Printf("[API] ERROR: Failed to parse BIM 360 Document Management response: %v", err)
		} else {
			log.Printf("[API] BIM 360 Document Management data: %+v", bimData)
			customAttrs["bim360_document_mgmt"] = bimData
			return customAttrs, nil
		}
	} else {
		log.Printf("[API] BIM 360 Document Management API returned HTTP %d: %s", bimResp.StatusCode, string(bimBody))
	}
	
	// Fallback: Try ACC Document Management API - single version endpoint
	accSingleURL := fmt.Sprintf("https://developer.api.autodesk.com/construction/documents/v1/projects/%s/versions/%s", cleanProjectID, itemID)
	log.Printf("[API] Trying ACC Document Management single version endpoint: %s", accSingleURL)
	
	accSingleResp, err := makeAuthorizedRequest(accSingleURL)
	if err == nil {
		defer accSingleResp.Body.Close()
		accSingleBody, err := io.ReadAll(accSingleResp.Body)
		if err == nil {
			log.Printf("[API] ACC single version response (status %d): %s", accSingleResp.StatusCode, string(accSingleBody))
			if accSingleResp.StatusCode == http.StatusOK {
				var accSingleData interface{}
				if json.Unmarshal(accSingleBody, &accSingleData) == nil {
					customAttrs["acc_single_version"] = accSingleData
					return customAttrs, nil
				}
			}
		}
	}
	
	log.Printf("[API] All ACC Document Management endpoints failed or returned empty results")
	return customAttrs, nil
}

func getCustomAttributesFromRelationships(projectID, itemID string) (map[string]interface{}, error) {
	log.Printf("[API] Fetching custom attributes from relationships for item %s in project %s", itemID, projectID)
	
	customAttrs := make(map[string]interface{})
	
	// Try BIM 360 Field API endpoints (ACC evolved from BIM 360)
	cleanProjectID := projectID
	if strings.HasPrefix(projectID, "b.") {
		cleanProjectID = projectID[2:]
	}
	
	// Try BIM 360 Field API custom attributes endpoint
	bim360URL := fmt.Sprintf("https://developer.api.autodesk.com/fieldapi/v1/projects/%s/custom-attributes", cleanProjectID)
	log.Printf("[API] Trying BIM 360 Field API custom attributes endpoint: %s", bim360URL)
	
	bim360Resp, err := makeAuthorizedRequest(bim360URL)
	if err != nil {
		log.Printf("[API] ERROR: Failed to request BIM 360 Field API custom attributes: %v", err)
	} else {
		defer bim360Resp.Body.Close()
		bim360Body, err := io.ReadAll(bim360Resp.Body)
		if err != nil {
			log.Printf("[API] ERROR: Failed to read BIM 360 Field API response: %v", err)
		} else {
			log.Printf("[API] BIM 360 Field API response (status %d): %s", bim360Resp.StatusCode, string(bim360Body))
			
			if bim360Resp.StatusCode == http.StatusOK {
				log.Printf("[API] SUCCESS: BIM 360 Field API is accessible!")
				var bim360Data interface{}
				err = json.Unmarshal(bim360Body, &bim360Data)
				if err != nil {
					log.Printf("[API] ERROR: Failed to parse BIM 360 Field API response: %v", err)
				} else {
					log.Printf("[API] BIM 360 Field API custom attributes: %+v", bim360Data)
					customAttrs["bim360_field_attributes"] = bim360Data
				}
			}
		}
	}
	
	// Try Construction Cloud API (ACC's native API)
	accURL := fmt.Sprintf("https://developer.api.autodesk.com/construction/admin/v1/projects/%s/custom-attributes", cleanProjectID)
	log.Printf("[API] Trying Construction Cloud API custom attributes endpoint: %s", accURL)
	
	accResp, err := makeAuthorizedRequest(accURL)
	if err != nil {
		log.Printf("[API] ERROR: Failed to request Construction Cloud API: %v", err)
	} else {
		defer accResp.Body.Close()
		accBody, err := io.ReadAll(accResp.Body)
		if err != nil {
			log.Printf("[API] ERROR: Failed to read Construction Cloud API response: %v", err)
		} else {
			log.Printf("[API] Construction Cloud API response (status %d): %s", accResp.StatusCode, string(accBody))
			
			if accResp.StatusCode == http.StatusOK {
				log.Printf("[API] SUCCESS: Construction Cloud API is accessible!")
				var accData interface{}
				err = json.Unmarshal(accBody, &accData)
				if err != nil {
					log.Printf("[API] ERROR: Failed to parse Construction Cloud API response: %v", err)
				} else {
					log.Printf("[API] Construction Cloud API custom attributes: %+v", accData)
					customAttrs["acc_custom_attributes"] = accData
				}
			}
		}
	}
	
	// Also try the DM v3 custom attributes definitions endpoint that ACC uses
	dmv3URL := fmt.Sprintf("https://developer.api.autodesk.com/dm/v3/projects/%s/custom-attribute-definitions?offset=0&limit=1000&sort=-id", cleanProjectID)
	log.Printf("[API] Trying DM v3 custom attribute definitions endpoint: %s", dmv3URL)
	
	dmv3Resp, err := makeAuthorizedRequest(dmv3URL)
	if err != nil {
		log.Printf("[API] ERROR: Failed to request DM v3 custom attributes: %v", err)
	} else {
		defer dmv3Resp.Body.Close()
		dmv3Body, err := io.ReadAll(dmv3Resp.Body)
		if err != nil {
			log.Printf("[API] ERROR: Failed to read DM v3 response: %v", err)
		} else {
			log.Printf("[API] DM v3 response (status %d): %s", dmv3Resp.StatusCode, string(dmv3Body))
			
			if dmv3Resp.StatusCode == http.StatusOK {
				log.Printf("[API] SUCCESS: DM v3 API is now accessible!")
				// Parse and use the custom attribute definitions
				var dmv3Data interface{}
				err = json.Unmarshal(dmv3Body, &dmv3Data)
				if err != nil {
					log.Printf("[API] ERROR: Failed to parse DM v3 response: %v", err)
				} else {
					log.Printf("[API] DM v3 custom attribute definitions: %+v", dmv3Data)
					customAttrs["dm_v3_definitions"] = dmv3Data
				}
			}
		}
	}
	
	// Try the refs endpoint
	refsURL := fmt.Sprintf("https://developer.api.autodesk.com/data/v1/projects/%s/items/%s/refs", projectID, itemID)
	log.Printf("[API] Trying refs endpoint: %s", refsURL)
	
	resp, err := makeAuthorizedRequest(refsURL)
	if err != nil {
		log.Printf("[API] ERROR: Failed to request refs: %v", err)
	} else {
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("[API] ERROR: Failed to read refs response: %v", err)
		} else {
			log.Printf("[API] Refs response (status %d): %s", resp.StatusCode, string(body))
			
			if resp.StatusCode == http.StatusOK {
				var refsResp interface{}
				err = json.Unmarshal(body, &refsResp)
				if err != nil {
					log.Printf("[API] ERROR: Failed to parse refs response: %v", err)
				} else {
					log.Printf("[API] Successfully retrieved refs: %+v", refsResp)
					// Check if refs contain custom attributes
					if refsMap, ok := refsResp.(map[string]interface{}); ok {
						if data, ok := refsMap["data"].([]interface{}); ok {
							for i, ref := range data {
								if refMap, ok := ref.(map[string]interface{}); ok {
									customAttrs[fmt.Sprintf("ref_%d", i)] = refMap
								}
							}
						}
					}
				}
			}
		}
	}
	
	// Also try the links endpoint
	linksURL := fmt.Sprintf("https://developer.api.autodesk.com/data/v1/projects/%s/items/%s/relationships/links", projectID, itemID)
	log.Printf("[API] Trying links endpoint: %s", linksURL)
	
	resp2, err := makeAuthorizedRequest(linksURL)
	if err != nil {
		log.Printf("[API] ERROR: Failed to request links: %v", err)
	} else {
		defer resp2.Body.Close()
		body2, err := io.ReadAll(resp2.Body)
		if err != nil {
			log.Printf("[API] ERROR: Failed to read links response: %v", err)
		} else {
			log.Printf("[API] Links response (status %d): %s", resp2.StatusCode, string(body2))
			
			if resp2.StatusCode == http.StatusOK {
				var linksResp interface{}
				err = json.Unmarshal(body2, &linksResp)
				if err != nil {
					log.Printf("[API] ERROR: Failed to parse links response: %v", err)
				} else {
					log.Printf("[API] Successfully retrieved links: %+v", linksResp)
					// Check if links contain custom attributes
					if linksMap, ok := linksResp.(map[string]interface{}); ok {
						if data, ok := linksMap["data"].([]interface{}); ok {
							for i, link := range data {
								if linkMap, ok := link.(map[string]interface{}); ok {
									customAttrs[fmt.Sprintf("link_%d", i)] = linkMap
								}
							}
						}
					}
				}
			}
		}
	}
	
	log.Printf("[API] Successfully extracted %d custom attributes from relationships", len(customAttrs))
	return customAttrs, nil
}

func getItemDetails(projectID, itemID string) (map[string]interface{}, error) {
	log.Printf("[API] Fetching detailed item information for item %s in project %s", itemID, projectID)
	
	// Get item details using the standard Data Management API
	itemURL := fmt.Sprintf("https://developer.api.autodesk.com/data/v1/projects/%s/items/%s", projectID, itemID)
	log.Printf("[API] Getting item details: %s", itemURL)
	
	resp, err := makeAuthorizedRequest(itemURL)
	if err != nil {
		log.Printf("[API] ERROR: Failed to request item details: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[API] ERROR: Failed to read item details response: %v", err)
		return nil, err
	}

	log.Printf("[API] Item details response (status %d): %s", resp.StatusCode, string(body))

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	// Parse the item details response
	var itemResp map[string]interface{}
	err = json.Unmarshal(body, &itemResp)
	if err != nil {
		log.Printf("[API] ERROR: Failed to parse item details response: %v", err)
		return nil, err
	}
	
	return itemResp, nil
}

func getAccCustomAttributes(projectID, itemID string) (map[string]interface{}, error) {
	log.Printf("[API] Fetching item attributes for item %s in project %s", itemID, projectID)
	
	// Try the Data Management API item attributes endpoint directly
	itemURL := fmt.Sprintf("https://developer.api.autodesk.com/data/v1/projects/%s/items/%s/attributes", projectID, itemID)
	log.Printf("[API] Getting item attributes: %s", itemURL)
	
	resp, err := makeAuthorizedRequest(itemURL)
	if err != nil {
		log.Printf("[API] ERROR: Failed to request item attributes: %v", err)
		return map[string]interface{}{}, nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[API] ERROR: Failed to read item attributes response: %v", err)
		return map[string]interface{}{}, nil
	}

	log.Printf("[API] Item attributes response (status %d): %s", resp.StatusCode, string(body))

	// Parse and return the attributes
	customAttrs := make(map[string]interface{})
	
	if resp.StatusCode == http.StatusOK {
		var attributesResp interface{}
		err = json.Unmarshal(body, &attributesResp)
		if err != nil {
			log.Printf("[API] ERROR: Failed to parse item attributes response: %v", err)
		} else {
			log.Printf("[API] Successfully retrieved item attributes: %+v", attributesResp)
			
			// Handle different possible response structures
			if attrMap, ok := attributesResp.(map[string]interface{}); ok {
				if data, ok := attrMap["data"].(map[string]interface{}); ok {
					customAttrs = data
				} else if results, ok := attrMap["results"].([]interface{}); ok {
					// Handle results array format
					for i, result := range results {
						if resultMap, ok := result.(map[string]interface{}); ok {
							for key, value := range resultMap {
								customAttrs[fmt.Sprintf("attr_%d_%s", i, key)] = value
							}
						}
					}
				} else {
					// Use the entire response as attributes
					customAttrs = attrMap
				}
			}
		}
	} else {
		log.Printf("[API] Item attributes endpoint returned HTTP %d: %s", resp.StatusCode, string(body))
	}
	
	log.Printf("[API] Successfully extracted %d custom attributes", len(customAttrs))
	return customAttrs, nil
}


func formatCustomAttributes(extensionData map[string]interface{}) string {
	log.Printf("[ATTRIBUTES] Processing extension data with %d total fields", len(extensionData))
	
	if len(extensionData) == 0 {
		log.Printf("[ATTRIBUTES] No extension data found")
		return "<em>No custom attributes</em>"
	}

	// Log all raw extension data first
	log.Printf("[ATTRIBUTES] Raw extension data:")
	for key, value := range extensionData {
		log.Printf("[ATTRIBUTES] - %s: %v (type: %T)", key, value, value)
	}

	var attributes []string
	var skippedCount int
	
	for key, value := range extensionData {
		// Skip system attributes (usually start with underscore or are complex objects)
		if strings.HasPrefix(key, "_") {
			log.Printf("[ATTRIBUTES] Skipping system attribute: %s", key)
			skippedCount++
			continue
		}
		
		// Convert value to string, handling different types
		var valueStr string
		switch v := value.(type) {
		case string:
			valueStr = v
			log.Printf("[ATTRIBUTES] String attribute %s: '%s'", key, v)
		case float64:
			valueStr = fmt.Sprintf("%.2f", v)
			log.Printf("[ATTRIBUTES] Numeric attribute %s: %f", key, v)
		case int:
			valueStr = fmt.Sprintf("%d", v)
			log.Printf("[ATTRIBUTES] Integer attribute %s: %d", key, v)
		case bool:
			valueStr = fmt.Sprintf("%t", v)
			log.Printf("[ATTRIBUTES] Boolean attribute %s: %t", key, v)
		default:
			// For complex types, convert to JSON
			jsonBytes, err := json.Marshal(v)
			if err != nil {
				valueStr = fmt.Sprintf("%v", v)
				log.Printf("[ATTRIBUTES] Complex attribute %s (marshal failed): %v", key, v)
			} else {
				valueStr = string(jsonBytes)
				log.Printf("[ATTRIBUTES] Complex attribute %s: %s", key, string(jsonBytes))
			}
		}

		// Truncate very long values for display (but log full value above)
		displayValue := valueStr
		if len(displayValue) > 50 {
			displayValue = displayValue[:47] + "..."
		}

		attributes = append(attributes, fmt.Sprintf("<strong>%s:</strong> %s", key, displayValue))
	}

	log.Printf("[ATTRIBUTES] Summary: %d total fields, %d skipped (system), %d custom attributes found", 
		len(extensionData), skippedCount, len(attributes))

	if len(attributes) == 0 {
		log.Printf("[ATTRIBUTES] No custom attributes after filtering")
		return "<em>No custom attributes</em>"
	}

	log.Printf("[ATTRIBUTES] Returning %d formatted custom attributes", len(attributes))
	return strings.Join(attributes, "<br>")
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
		RefreshToken: tokenResp.RefreshToken,
		AccessToken:  tokenResp.AccessToken,
		ExpiresAt:    time.Now().Unix() + int64(tokenResp.ExpiresIn),
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

func refreshAccessToken(refreshToken string) (*TokenResponse, error) {
	log.Printf("[AUTH] Refreshing access token using stored refresh token...")
	log.Printf("[AUTH] Refresh token (first 20 chars): %s***", refreshToken[:20])
	
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", config.ClientID)
	data.Set("client_secret", config.ClientSecret)

	req, err := http.NewRequest("POST", "https://developer.api.autodesk.com/authentication/v2/token", strings.NewReader(data.Encode()))
	if err != nil {
		log.Printf("[AUTH] ERROR: Failed to create refresh request: %v", err)
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[AUTH] ERROR: Refresh token request failed: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	log.Printf("[AUTH] Refresh token response received with status: %d", resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[AUTH] ERROR: Failed to read refresh response: %v", err)
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("[AUTH] ERROR: Refresh token failed with HTTP %d: %s", resp.StatusCode, string(body))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	err = json.Unmarshal(body, &tokenResp)
	if err != nil {
		log.Printf("[AUTH] ERROR: Failed to parse refresh response: %v", err)
		return nil, err
	}

	log.Printf("[AUTH] Access token refreshed successfully (expires in %d seconds)", tokenResp.ExpiresIn)
	
	// Update stored token with new access token and expiry
	if tokenResp.RefreshToken == "" {
		// If no new refresh token provided, keep the old one
		tokenResp.RefreshToken = refreshToken
	}
	
	err = saveTokenToDisk(&tokenResp)
	if err != nil {
		log.Printf("[AUTH] WARNING: Failed to save refreshed token: %v", err)
	}

	return &tokenResp, nil
}

func tryAutomaticAuthentication() bool {
	log.Printf("[AUTH] Checking for stored refresh token...")
	
	stored, err := loadTokenFromDisk()
	if err != nil {
		log.Printf("[AUTH] No stored token found: %v", err)
		return false
	}

	// Check if current access token is still valid (with 5 minute buffer)
	if stored.ExpiresAt > time.Now().Unix()+300 {
		log.Printf("[AUTH] Stored access token is still valid, using it")
		token = &TokenResponse{
			AccessToken:  stored.AccessToken,
			RefreshToken: stored.RefreshToken,
			TokenType:    "Bearer",
			ExpiresIn:    int(stored.ExpiresAt - time.Now().Unix()),
		}
		return true
	}

	log.Printf("[AUTH] Stored access token expired, refreshing...")
	newToken, err := refreshAccessToken(stored.RefreshToken)
	if err != nil {
		log.Printf("[AUTH] ERROR: Failed to refresh token: %v", err)
		log.Printf("[AUTH] You may need to re-authenticate via /login")
		return false
	}

	token = newToken
	log.Printf("[AUTH] Successfully authenticated using stored refresh token")
	return true
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
	
	// Build the signed URL for this file
	downloadURLParams := fmt.Sprintf("projectId=%s&itemId=%s&fileName=%s",
		url.QueryEscape(projectID),
		url.QueryEscape(itemID),
		url.QueryEscape(fileName))
	
	if versionNumber != "" {
		downloadURLParams += fmt.Sprintf("&versionNumber=%s", url.QueryEscape(versionNumber))
	}
	
	downloadURL := fmt.Sprintf("/download?%s", downloadURLParams)
	
	html := fmt.Sprintf(`
<!doctype html>
<html>
<head>
    <title>PDF Viewer - %s</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 0; 
            padding: 0;
            background-color: #f5f5f5;
        }
        .header { 
            padding: 15px 20px; 
            background-color: white; 
            border-bottom: 1px solid #ddd;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .header h2 { 
            margin: 0 0 10px 0; 
            color: #333;
        }
        .header p { 
            margin: 5px 0; 
            color: #666;
        }
        .header a { 
            color: #007bff; 
            text-decoration: none;
        }
        .header a:hover { 
            text-decoration: underline;
        }
        .viewer-container {
            position: relative;
            height: calc(100vh - 120px);
            margin: 20px;
            border: 1px solid #ddd;
            border-radius: 8px;
            overflow: hidden;
            background-color: white;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }
        .loading-overlay {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%%;
            height: 100%%;
            background-color: rgba(255,255,255,0.9);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 18px;
            color: #666;
            z-index: 1000;
        }
        .pdf-embed {
            width: 100%%;
            height: 100%%;
            border: none;
        }
        .error-message {
            padding: 20px;
            text-align: center;
            color: #dc3545;
            background-color: #f8d7da;
            margin: 20px;
            border-radius: 4px;
            border: 1px solid #f5c6cb;
        }
    </style>
</head>
<body>
    <div class="header">
        <h2>📄 PDF Viewer</h2>
        <p><strong>File:</strong> %s</p>
        <p><a href="javascript:history.back()">← Back to Versions</a> | 
           <a href="%s" target="_blank">📥 Download PDF</a></p>
    </div>
    
    <div class="viewer-container">
        <div class="loading-overlay" id="loadingOverlay">
            🔄 Loading PDF viewer...
        </div>
        <embed id="pdfEmbed" class="pdf-embed" type="application/pdf" style="display: none;">
    </div>

    <script>
        async function loadPDF() {
            const loadingOverlay = document.getElementById('loadingOverlay');
            const pdfEmbed = document.getElementById('pdfEmbed');
            
            try {
                // First get the signed download URL from our server
                const downloadResponse = await fetch('%s');
                if (!downloadResponse.ok) {
                    throw new Error('Failed to get download URL: ' + downloadResponse.statusText);
                }
                
                // Get the actual signed S3 URL
                const signedURL = downloadResponse.url;
                
                // Use our CORS proxy for the PDF
                const proxyURL = '/pdf-proxy?url=' + encodeURIComponent(signedURL);
                
                // Set the PDF source and show it
                pdfEmbed.src = proxyURL;
                pdfEmbed.style.display = 'block';
                
                // Hide loading overlay after a short delay to allow PDF to start loading
                setTimeout(() => {
                    loadingOverlay.style.display = 'none';
                }, 1500);
                
            } catch (error) {
                console.error('Error loading PDF:', error);
                loadingOverlay.innerHTML = '❌ Error loading PDF: ' + error.message + 
                    '<br><br><a href="javascript:location.reload()">Try Again</a>';
            }
        }
        
        // Auto-load PDF when page loads
        window.onload = function() {
            loadPDF();
        };
    </script>
</body>
</html>`, fileName, fileName, downloadURL, downloadURL)
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, html)
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
