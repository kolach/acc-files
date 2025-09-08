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
		<p><em>Your refresh token is saved. This app can now run without user interaction.</em></p>`
	} else {
		authStatus = "❌ <strong>Not authenticated</strong> - Manual login required"
		actions = `
		<p><a href="/login">Login with Autodesk</a> (this will save your refresh token)</p>`
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
			html += "<h3>❌ Cannot test - no stored token</h3>"
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
			func() string {
				if i == 0 {
					return " (Latest)"
				} else {
					return ""
				}
			}(),
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
	var batchCustomAttributes map[string]any
	if len(fileURNs) > 0 {
		batchCustomAttributes, err = getBatchCustomAttributes(projectID, fileURNs)
		if err != nil {
			log.Printf("[HANDLER] WARNING: Batch custom attributes request failed: %v", err)
			batchCustomAttributes = make(map[string]any)
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
		return "<em>No custom attributes</em>"
	}

	// Handle string response
	if str, ok := attrs.(string); ok {
		return fmt.Sprintf("<em>%s</em>", str)
	}

	// Handle array of custom attributes
	if attrArray, ok := attrs.([]any); ok {
		if len(attrArray) == 0 {
			return "<em>No custom attributes assigned</em>"
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
