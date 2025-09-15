# Autodesk ACC File Browser

A Go web application that demonstrates **Autodesk APS (Platform Services) 2-legged authentication** for accessing and browsing project files in Autodesk Construction Cloud (ACC). The application provides file browsing, version history, downloads, and PDF viewing capabilities for a single configured project.

## Features

- **2-Legged Authentication**: Server-to-server authentication using client credentials (no user login required)
- **Single Project Focus**: Configured to work with one specific project via environment variables
- **File Browser**: Navigate project folders and view file listings with custom attributes
- **Version History**: View complete version history for any file
- **File Downloads**: Direct download files via signed S3 URLs
- **PDF Viewer**: Built-in PDF viewer with CORS proxy for cloud-hosted files
- **Token Management**: Automatic token refresh and persistent storage
- **Custom Attributes**: Display BIM 360/ACC custom file attributes

## Quick Start

### Prerequisites

- Go 1.24.2 or later
- Autodesk APS application credentials with `data:read` scope

### 1. Get APS Credentials

1. Visit the [Autodesk APS Developer Portal](https://aps.autodesk.com/myapps)
2. Create a new application or use existing one
3. Ensure it has `data:read` scope enabled
4. Note your **Client ID** and **Client Secret**

### 2. Configure Environment

Copy the example environment file:
```bash
cp .env.example .env
```

Edit `.env` with your credentials and project information:
```bash
# Required - Get these from APS Developer Portal
export APS_CLIENT_ID=your_client_id_here
export APS_CLIENT_SECRET=your_client_secret_here

# Project Configuration - specify which hub and project to work with
export APS_HUB_ID=your_hub_id_here
export APS_PROJECT_ID=your_project_id_here

export PORT="8080"
```

### 3. Install Dependencies

```bash
go mod tidy
```

### 4. Run the Application

```bash
go run main.go
```

Or build and run:
```bash
go build -o acc-files main.go
./acc-files
```

The application will be available at `http://localhost:8080`

## Usage

1. **Home Page** (`/`): Shows authentication status
2. **Projects** (`/projects`): Displays your configured project with root folder access
3. **Files** (`/files`): Browse project files and folders with custom attributes
4. **Token Status** (`/token-status`): Debug interface for token management

### Navigation Flow

1. Start at home page to verify authentication
2. Go to `/projects` to see your configured project
3. Click "Browse Files" to explore the project file structure
4. View version history, download files, or open PDFs in the browser

## Project Structure

```
├── main.go                 # Main application with all handlers and API calls
├── templates/             # HTML templates
│   ├── home.html         # Landing page
│   ├── projects.html     # Project details
│   ├── files.html        # File browser
│   ├── versions.html     # Version history
│   ├── viewer.html       # PDF viewer
│   └── token-status.html # Token debug page
├── autodesk_token.json   # Persistent token storage (auto-created)
├── .env                  # Environment configuration
└── README.md
```

## API Integration

The application integrates with multiple Autodesk APS APIs:

- **Authentication API**: 2-legged OAuth token management
- **Project API**: Project details and root folder access
- **Data API**: File and folder browsing, version history
- **OSS API**: Signed S3 download URLs
- **BIM 360 Document Management API**: Custom file attributes

## Key Features Explained

### 2-Legged Authentication
- Uses client credentials flow (no user interaction)
- Tokens are automatically refreshed on expiry
- Persistent token storage in `autodesk_token.json`

### Single Project Configuration
- Configured via `APS_HUB_ID` and `APS_PROJECT_ID` environment variables
- No project browsing - directly accesses the configured project
- Optimized for focused project work

### File Operations
- **Browse**: Navigate folder hierarchy starting from project root
- **Download**: Stream files directly from Autodesk cloud storage
- **View**: Built-in PDF viewer with CORS proxy support
- **Versions**: Complete version history with download links

### Custom Attributes
- Batch retrieval of BIM 360/ACC custom attributes
- Displayed alongside file information
- Supports all custom attribute types

## Development Commands

```bash
# Run application
go run main.go

# Build binary
go build -o acc-files main.go

# Format code
go fmt ./...

# Static analysis
go vet ./...

# Clean dependencies
go mod tidy
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `APS_CLIENT_ID` | Yes | Autodesk APS application client ID |
| `APS_CLIENT_SECRET` | Yes | Autodesk APS application client secret |
| `APS_HUB_ID` | Yes | Hub ID containing the project |
| `APS_PROJECT_ID` | Yes | Project ID to work with |
| `PORT` | No | Server port (default: 8080) |

## Authentication Flow

1. Application starts and checks for valid stored token
2. If no valid token exists, requests new token using client credentials
3. Token is saved to `autodesk_token.json` with expiry information
4. On API calls, if token is expired, automatically refreshes and retries
5. All API calls include automatic retry logic for expired tokens

## Troubleshooting

### Authentication Issues
- Verify `APS_CLIENT_ID` and `APS_CLIENT_SECRET` are correct
- Ensure your APS application has `data:read` scope
- Check `/token-status` page for token details and manual refresh

### Project Access Issues
- Verify `APS_HUB_ID` and `APS_PROJECT_ID` point to accessible project
- Ensure your APS application has access to the specified project
- Check that the project exists and is active

### File Access Issues
- Some files may require additional permissions
- Custom attributes require BIM 360/ACC project setup
- Download failures may indicate expired signed URLs (automatically retried)

## Dependencies

- **Go 1.24.2+**: Core language runtime
- **github.com/joho/godotenv**: Environment variable loading from .env files

## License

This project is provided as-is for demonstration purposes. Check Autodesk APS terms of service for API usage requirements.