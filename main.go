package main

import (
    "context"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "database/sql"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net/http"
    "os"
    "os/exec"
    "path/filepath"
    "strconv"
    "strings"
    "sync"
    "time"

    "cloud.google.com/go/storage"
    _ "github.com/jackc/pgx/v5/stdlib"
    "github.com/joho/godotenv"
    "golang.org/x/oauth2"
    "golang.org/x/oauth2/google"
    "google.golang.org/api/googleapi"
    "google.golang.org/api/option"
    "google.golang.org/api/youtube/v3"
)

// Asset represents a media file in the system
type Asset struct {
    ID            int       `json:"id"`
    Name          string    `json:"name"`
    Size          int64     `json:"size"`
    MimeType      string    `json:"mime_type"`
    Status        string    `json:"status"` // pending, approved, rejected, uploaded
    GCSPath       string    `json:"gcs_path"`
    ThumbnailPath *string   `json:"thumbnail_path,omitempty"`
    PreviewPath   *string   `json:"preview_path,omitempty"`
    YouTubeID     *string   `json:"youtube_id,omitempty"`
    CreatedAt     time.Time `json:"created_at"`
    UpdatedAt     time.Time `json:"updated_at"`
}

// YouTubeVideo represents an uploaded YouTube video linked to an asset
type YouTubeVideo struct {
    ID            int       `json:"id"`
    AssetID       int       `json:"asset_id"`
    YouTubeID     string    `json:"youtube_id"`
    Title         string    `json:"title,omitempty"`
    PrivacyStatus string    `json:"privacy_status"`
    CreatedAt     time.Time `json:"created_at"`
}

// AssetStore manages assets in PostgreSQL
type AssetStore struct {
    db *sql.DB
}

func NewAssetStore(db *sql.DB) *AssetStore {
    return &AssetStore{db: db}
}

func (s *AssetStore) Create(ctx context.Context, asset *Asset) (*Asset, error) {
    query := `
        INSERT INTO assets (name, size, mime_type, status, gcs_path)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, created_at, updated_at`
    err := s.db.QueryRowContext(ctx, query,
        asset.Name, asset.Size, asset.MimeType, asset.Status, asset.GCSPath,
    ).Scan(&asset.ID, &asset.CreatedAt, &asset.UpdatedAt)
    if err != nil {
        return nil, err
    }
    return asset, nil
}

func (s *AssetStore) Get(ctx context.Context, id int) (*Asset, error) {
    query := `
        SELECT a.id, a.name, a.size, a.mime_type, a.status, a.gcs_path,
               a.thumbnail_path, a.preview_path, yv.youtube_id, a.created_at, a.updated_at
        FROM assets a
        LEFT JOIN youtube_videos yv ON a.id = yv.asset_id
        WHERE a.id = $1`
    asset := &Asset{}
    err := s.db.QueryRowContext(ctx, query, id).Scan(
        &asset.ID, &asset.Name, &asset.Size, &asset.MimeType,
        &asset.Status, &asset.GCSPath, &asset.ThumbnailPath, &asset.PreviewPath, &asset.YouTubeID,
        &asset.CreatedAt, &asset.UpdatedAt,
    )
    if err == sql.ErrNoRows {
        return nil, nil
    }
    if err != nil {
        return nil, err
    }
    return asset, nil
}

func (s *AssetStore) List(ctx context.Context, status string) ([]*Asset, error) {
    var query string
    var args []interface{}
    if status != "" {
        query = `
            SELECT a.id, a.name, a.size, a.mime_type, a.status, a.gcs_path,
                   a.thumbnail_path, a.preview_path, yv.youtube_id, a.created_at, a.updated_at
            FROM assets a
            LEFT JOIN youtube_videos yv ON a.id = yv.asset_id
            WHERE a.status = $1 ORDER BY a.created_at DESC`
        args = []interface{}{status}
    } else {
        query = `
            SELECT a.id, a.name, a.size, a.mime_type, a.status, a.gcs_path,
                   a.thumbnail_path, a.preview_path, yv.youtube_id, a.created_at, a.updated_at
            FROM assets a
            LEFT JOIN youtube_videos yv ON a.id = yv.asset_id
            ORDER BY a.created_at DESC`
    }

    rows, err := s.db.QueryContext(ctx, query, args...)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var assets []*Asset
    for rows.Next() {
        asset := &Asset{}
        err := rows.Scan(
            &asset.ID, &asset.Name, &asset.Size, &asset.MimeType,
            &asset.Status, &asset.GCSPath, &asset.ThumbnailPath, &asset.PreviewPath, &asset.YouTubeID,
            &asset.CreatedAt, &asset.UpdatedAt,
        )
        if err != nil {
            return nil, err
        }
        assets = append(assets, asset)
    }
    return assets, rows.Err()
}

func (s *AssetStore) Update(ctx context.Context, id int, status string) (*Asset, error) {
    // Update the asset
    _, err := s.db.ExecContext(ctx, `UPDATE assets SET status = $1, updated_at = NOW() WHERE id = $2`, status, id)
    if err != nil {
        return nil, err
    }
    // Fetch with youtube_id join
    return s.Get(ctx, id)
}

func (s *AssetStore) Delete(ctx context.Context, id int) error {
    _, err := s.db.ExecContext(ctx, "DELETE FROM assets WHERE id = $1", id)
    return err
}

func (s *AssetStore) UpdateThumbnailPath(ctx context.Context, id int, thumbnailPath string) error {
    _, err := s.db.ExecContext(ctx,
        `UPDATE assets SET thumbnail_path = $1, updated_at = NOW() WHERE id = $2`,
        thumbnailPath, id)
    return err
}

func (s *AssetStore) UpdatePreviewPath(ctx context.Context, id int, previewPath string) error {
    _, err := s.db.ExecContext(ctx,
        `UPDATE assets SET preview_path = $1, updated_at = NOW() WHERE id = $2`,
        previewPath, id)
    return err
}

// YouTubeVideoStore manages YouTube video records in PostgreSQL
type YouTubeVideoStore struct {
    db *sql.DB
}

func NewYouTubeVideoStore(db *sql.DB) *YouTubeVideoStore {
    return &YouTubeVideoStore{db: db}
}

func (s *YouTubeVideoStore) Create(ctx context.Context, video *YouTubeVideo) (*YouTubeVideo, error) {
    query := `
        INSERT INTO youtube_videos (asset_id, youtube_id, title, privacy_status)
        VALUES ($1, $2, $3, $4)
        RETURNING id, created_at`
    err := s.db.QueryRowContext(ctx, query,
        video.AssetID, video.YouTubeID, video.Title, video.PrivacyStatus,
    ).Scan(&video.ID, &video.CreatedAt)
    if err != nil {
        return nil, err
    }
    return video, nil
}

func (s *YouTubeVideoStore) GetByAssetID(ctx context.Context, assetID int) (*YouTubeVideo, error) {
    query := `
        SELECT id, asset_id, youtube_id, title, privacy_status, created_at
        FROM youtube_videos WHERE asset_id = $1`
    video := &YouTubeVideo{}
    err := s.db.QueryRowContext(ctx, query, assetID).Scan(
        &video.ID, &video.AssetID, &video.YouTubeID, &video.Title,
        &video.PrivacyStatus, &video.CreatedAt,
    )
    if err == sql.ErrNoRows {
        return nil, nil
    }
    if err != nil {
        return nil, err
    }
    return video, nil
}

// Encryption helpers using AES-GCM

func encrypt(plaintext string, key []byte) (string, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }

    ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decrypt(ciphertext string, key []byte) (string, error) {
    data, err := base64.StdEncoding.DecodeString(ciphertext)
    if err != nil {
        return "", err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    if len(data) < gcm.NonceSize() {
        return "", fmt.Errorf("ciphertext too short")
    }

    nonce, ciphertext := data[:gcm.NonceSize()], string(data[gcm.NonceSize():])
    plaintext, err := gcm.Open(nil, nonce, []byte(ciphertext), nil)
    if err != nil {
        return "", err
    }

    return string(plaintext), nil
}

// TokenStore manages YouTube OAuth tokens in PostgreSQL
type TokenStore struct {
    db            *sql.DB
    encryptionKey []byte
}

func NewTokenStore(db *sql.DB, encryptionKey []byte) *TokenStore {
    return &TokenStore{db: db, encryptionKey: encryptionKey}
}

func (s *TokenStore) Save(ctx context.Context, token *oauth2.Token) error {
    // Encrypt sensitive token fields
    encAccessToken, err := encrypt(token.AccessToken, s.encryptionKey)
    if err != nil {
        return fmt.Errorf("failed to encrypt access token: %w", err)
    }
    encRefreshToken, err := encrypt(token.RefreshToken, s.encryptionKey)
    if err != nil {
        return fmt.Errorf("failed to encrypt refresh token: %w", err)
    }

    // Delete existing tokens and insert new one
    _, err = s.db.ExecContext(ctx, "DELETE FROM youtube_tokens")
    if err != nil {
        return err
    }
    query := `
        INSERT INTO youtube_tokens (access_token, refresh_token, token_type, expiry)
        VALUES ($1, $2, $3, $4)`
    _, err = s.db.ExecContext(ctx, query,
        encAccessToken, encRefreshToken, token.TokenType, token.Expiry,
    )
    return err
}

func (s *TokenStore) Get(ctx context.Context) (*oauth2.Token, error) {
    query := `
        SELECT access_token, refresh_token, token_type, expiry
        FROM youtube_tokens ORDER BY id DESC LIMIT 1`
    var encAccessToken, encRefreshToken string
    token := &oauth2.Token{}
    err := s.db.QueryRowContext(ctx, query).Scan(
        &encAccessToken, &encRefreshToken, &token.TokenType, &token.Expiry,
    )
    if err == sql.ErrNoRows {
        return nil, nil
    }
    if err != nil {
        return nil, err
    }

    // Decrypt token fields
    token.AccessToken, err = decrypt(encAccessToken, s.encryptionKey)
    if err != nil {
        return nil, fmt.Errorf("failed to decrypt access token: %w", err)
    }
    token.RefreshToken, err = decrypt(encRefreshToken, s.encryptionKey)
    if err != nil {
        return nil, fmt.Errorf("failed to decrypt refresh token: %w", err)
    }

    return token, nil
}

// AssetEvent represents an SSE event for asset updates
type AssetEvent struct {
    Type  string `json:"type"`  // "asset_updated"
    Asset *Asset `json:"asset"`
}

// Server holds the HTTP server dependencies
type Server struct {
    store             *AssetStore
    tokenStore        *TokenStore
    youtubeVideoStore *YouTubeVideoStore
    gcsClient         *storage.Client
    bucketName        string
    youtubeOAuth      *oauth2.Config

    // SSE clients
    sseClients   map[chan AssetEvent]struct{}
    sseMu        sync.RWMutex
}

func NewServer(db *sql.DB, bucketName string, ytClientID, ytClientSecret string, encryptionKey []byte) (*Server, error) {
    ctx := context.Background()
    client, err := storage.NewClient(ctx)
    if err != nil {
        return nil, fmt.Errorf("storage.NewClient: %v", err)
    }

    var youtubeOAuth *oauth2.Config
    if ytClientID != "" && ytClientSecret != "" {
        youtubeOAuth = &oauth2.Config{
            ClientID:     ytClientID,
            ClientSecret: ytClientSecret,
            Endpoint:     google.Endpoint,
            RedirectURL:  "http://localhost:8080/api/auth/youtube/callback",
            Scopes:       []string{youtube.YoutubeUploadScope},
        }
    }

    return &Server{
        store:             NewAssetStore(db),
        tokenStore:        NewTokenStore(db, encryptionKey),
        youtubeVideoStore: NewYouTubeVideoStore(db),
        gcsClient:         client,
        bucketName:        bucketName,
        youtubeOAuth:      youtubeOAuth,
        sseClients:        make(map[chan AssetEvent]struct{}),
    }, nil
}

func (s *Server) Close() error {
    return s.gcsClient.Close()
}

// SSE methods

func (s *Server) sseSubscribe() chan AssetEvent {
    ch := make(chan AssetEvent, 10)
    s.sseMu.Lock()
    s.sseClients[ch] = struct{}{}
    s.sseMu.Unlock()
    return ch
}

func (s *Server) sseUnsubscribe(ch chan AssetEvent) {
    s.sseMu.Lock()
    delete(s.sseClients, ch)
    s.sseMu.Unlock()
    close(ch)
}

func (s *Server) sseBroadcast(event AssetEvent) {
    s.sseMu.RLock()
    defer s.sseMu.RUnlock()
    for ch := range s.sseClients {
        select {
        case ch <- event:
        default:
            // Client too slow, skip
        }
    }
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
    // Set SSE headers
    w.Header().Set("Content-Type", "text/event-stream")
    w.Header().Set("Cache-Control", "no-cache")
    w.Header().Set("Connection", "keep-alive")
    w.Header().Set("Access-Control-Allow-Origin", "*")

    // Subscribe to events
    ch := s.sseSubscribe()
    defer s.sseUnsubscribe(ch)

    // Flush initial connection
    if flusher, ok := w.(http.Flusher); ok {
        flusher.Flush()
    }

    // Send events until client disconnects
    for {
        select {
        case <-r.Context().Done():
            return
        case event := <-ch:
            data, err := json.Marshal(event)
            if err != nil {
                log.Printf("SSE marshal error: %v", err)
                continue
            }
            fmt.Fprintf(w, "data: %s\n\n", data)
            if flusher, ok := w.(http.Flusher); ok {
                flusher.Flush()
            }
        }
    }
}

// CORS middleware for React/mobile clients
func corsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Access-Control-Allow-Origin", "*")
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
        if r.Method == "OPTIONS" {
            w.WriteHeader(http.StatusOK)
            return
        }
        next.ServeHTTP(w, r)
    })
}

func getMimeType(filename string) string {
    ext := strings.ToLower(filepath.Ext(filename))
    mimeTypes := map[string]string{
        ".mp4":  "video/mp4",
        ".mov":  "video/quicktime",
        ".avi":  "video/x-msvideo",
        ".mkv":  "video/x-matroska",
        ".webm": "video/webm",
        ".mp3":  "audio/mpeg",
        ".wav":  "audio/wav",
        ".aac":  "audio/aac",
        ".flac": "audio/flac",
        ".m4a":  "audio/mp4",
    }
    if mime, ok := mimeTypes[ext]; ok {
        return mime
    }
    return "application/octet-stream"
}

func isMediaFile(name string) bool {
    extensions := []string{".mp4", ".mov", ".avi", ".mkv", ".webm", ".mp3", ".wav", ".aac", ".flac", ".m4a"}
    lower := strings.ToLower(name)
    for _, ext := range extensions {
        if strings.HasSuffix(lower, ext) {
            return true
        }
    }
    return false
}

func isVideoFile(name string) bool {
    extensions := []string{".mp4", ".mov", ".avi", ".mkv", ".webm"}
    lower := strings.ToLower(name)
    for _, ext := range extensions {
        if strings.HasSuffix(lower, ext) {
            return true
        }
    }
    return false
}

// generateThumbnail creates a thumbnail from a video file using ffmpeg
// Downloads from GCS, generates thumbnail, uploads back to GCS
func (s *Server) generateThumbnail(ctx context.Context, asset *Asset) error {
    if !isVideoFile(asset.Name) {
        return nil // Skip non-video files
    }

    // Create temp files
    tempVideo, err := os.CreateTemp("", "video-*"+filepath.Ext(asset.Name))
    if err != nil {
        return fmt.Errorf("failed to create temp video file: %w", err)
    }
    defer os.Remove(tempVideo.Name())
    defer tempVideo.Close()

    tempThumb, err := os.CreateTemp("", "thumb-*.jpg")
    if err != nil {
        return fmt.Errorf("failed to create temp thumbnail file: %w", err)
    }
    defer os.Remove(tempThumb.Name())
    tempThumb.Close()

    // Download video from GCS
    obj := s.gcsClient.Bucket(s.bucketName).Object(asset.GCSPath)
    reader, err := obj.NewReader(ctx)
    if err != nil {
        return fmt.Errorf("failed to read from GCS: %w", err)
    }
    defer reader.Close()

    if _, err := io.Copy(tempVideo, reader); err != nil {
        return fmt.Errorf("failed to download video: %w", err)
    }
    tempVideo.Close()

    // Generate thumbnail with ffmpeg (capture frame at 1 second, scale to 320px width)
    cmd := exec.CommandContext(ctx, "ffmpeg",
        "-i", tempVideo.Name(),
        "-ss", "00:00:01",
        "-vframes", "1",
        "-vf", "scale=320:-1",
        "-y",
        tempThumb.Name(),
    )
    if output, err := cmd.CombinedOutput(); err != nil {
        return fmt.Errorf("ffmpeg failed: %w, output: %s", err, string(output))
    }

    // Upload thumbnail to GCS
    thumbnailPath := fmt.Sprintf("thumbnails/%d.jpg", asset.ID)
    thumbReader, err := os.Open(tempThumb.Name())
    if err != nil {
        return fmt.Errorf("failed to open thumbnail: %w", err)
    }
    defer thumbReader.Close()

    wc := s.gcsClient.Bucket(s.bucketName).Object(thumbnailPath).NewWriter(ctx)
    wc.ContentType = "image/jpeg"
    if _, err := io.Copy(wc, thumbReader); err != nil {
        return fmt.Errorf("failed to upload thumbnail: %w", err)
    }
    if err := wc.Close(); err != nil {
        return fmt.Errorf("failed to close GCS writer: %w", err)
    }

    // Update asset with thumbnail path
    if err := s.store.UpdateThumbnailPath(ctx, asset.ID, thumbnailPath); err != nil {
        return fmt.Errorf("failed to update thumbnail path: %w", err)
    }

    log.Printf("Generated thumbnail for asset %d: %s", asset.ID, thumbnailPath)

    // Broadcast SSE event
    updatedAsset, err := s.store.Get(ctx, asset.ID)
    if err == nil && updatedAsset != nil {
        s.sseBroadcast(AssetEvent{Type: "asset_updated", Asset: updatedAsset})
    }

    return nil
}

// generatePreview creates a low-resolution MP4 preview from a video file using ffmpeg
// Downloads from GCS, transcodes to low-res MP4, uploads back to GCS
func (s *Server) generatePreview(ctx context.Context, asset *Asset) error {
    if !isVideoFile(asset.Name) {
        return nil // Skip non-video files
    }

    // Create temp files
    tempVideo, err := os.CreateTemp("", "video-*"+filepath.Ext(asset.Name))
    if err != nil {
        return fmt.Errorf("failed to create temp video file: %w", err)
    }
    defer os.Remove(tempVideo.Name())
    defer tempVideo.Close()

    tempPreview, err := os.CreateTemp("", "preview-*.mp4")
    if err != nil {
        return fmt.Errorf("failed to create temp preview file: %w", err)
    }
    defer os.Remove(tempPreview.Name())
    tempPreview.Close()

    // Download video from GCS
    obj := s.gcsClient.Bucket(s.bucketName).Object(asset.GCSPath)
    reader, err := obj.NewReader(ctx)
    if err != nil {
        return fmt.Errorf("failed to read from GCS: %w", err)
    }
    defer reader.Close()

    if _, err := io.Copy(tempVideo, reader); err != nil {
        return fmt.Errorf("failed to download video: %w", err)
    }
    tempVideo.Close()

    // Generate low-res preview with ffmpeg
    // Scale to 480p height, use H.264 codec, reduce bitrate for smaller file size
    cmd := exec.CommandContext(ctx, "ffmpeg",
        "-i", tempVideo.Name(),
        "-vf", "scale=-2:480",           // Scale to 480p height, width auto (divisible by 2)
        "-c:v", "libx264",               // H.264 video codec
        "-preset", "fast",               // Encoding speed/quality tradeoff
        "-crf", "28",                    // Quality (higher = smaller file, lower quality)
        "-c:a", "aac",                   // AAC audio codec
        "-b:a", "128k",                  // Audio bitrate
        "-movflags", "+faststart",       // Enable streaming (metadata at start)
        "-y",
        tempPreview.Name(),
    )
    if output, err := cmd.CombinedOutput(); err != nil {
        return fmt.Errorf("ffmpeg failed: %w, output: %s", err, string(output))
    }

    // Upload preview to GCS
    previewPath := fmt.Sprintf("previews/%d.mp4", asset.ID)
    previewReader, err := os.Open(tempPreview.Name())
    if err != nil {
        return fmt.Errorf("failed to open preview: %w", err)
    }
    defer previewReader.Close()

    wc := s.gcsClient.Bucket(s.bucketName).Object(previewPath).NewWriter(ctx)
    wc.ContentType = "video/mp4"
    if _, err := io.Copy(wc, previewReader); err != nil {
        return fmt.Errorf("failed to upload preview: %w", err)
    }
    if err := wc.Close(); err != nil {
        return fmt.Errorf("failed to close GCS writer: %w", err)
    }

    // Update asset with preview path
    if err := s.store.UpdatePreviewPath(ctx, asset.ID, previewPath); err != nil {
        return fmt.Errorf("failed to update preview path: %w", err)
    }

    log.Printf("Generated preview for asset %d: %s", asset.ID, previewPath)

    // Broadcast SSE event
    updatedAsset, err := s.store.Get(ctx, asset.ID)
    if err == nil && updatedAsset != nil {
        s.sseBroadcast(AssetEvent{Type: "asset_updated", Asset: updatedAsset})
    }

    return nil
}

// Handlers

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    // Parse multipart form (max 500MB)
    if err := r.ParseMultipartForm(500 << 20); err != nil {
        http.Error(w, "Failed to parse form: "+err.Error(), http.StatusBadRequest)
        return
    }

    file, header, err := r.FormFile("file")
    if err != nil {
        http.Error(w, "Failed to get file: "+err.Error(), http.StatusBadRequest)
        return
    }
    defer file.Close()

    if !isMediaFile(header.Filename) {
        http.Error(w, "Only video/audio files are allowed", http.StatusBadRequest)
        return
    }

    // Upload to GCS
    ctx := r.Context()
    objectName := fmt.Sprintf("uploads/%d_%s", time.Now().UnixNano(), header.Filename)
    wc := s.gcsClient.Bucket(s.bucketName).Object(objectName).NewWriter(ctx)
    wc.ContentType = getMimeType(header.Filename)

    if _, err = io.Copy(wc, file); err != nil {
        http.Error(w, "Failed to upload to GCS: "+err.Error(), http.StatusInternalServerError)
        return
    }
    if err := wc.Close(); err != nil {
        http.Error(w, "Failed to close GCS writer: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Create asset record
    asset, err := s.store.Create(ctx, &Asset{
        Name:     header.Filename,
        Size:     header.Size,
        MimeType: getMimeType(header.Filename),
        Status:   "pending",
        GCSPath:  objectName,
    })
    if err != nil {
        http.Error(w, "Failed to create asset record: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Generate thumbnail and preview in background
    go func() {
        bgCtx := context.Background()
        if err := s.generateThumbnail(bgCtx, asset); err != nil {
            log.Printf("Failed to generate thumbnail for asset %d: %v", asset.ID, err)
        }
        if err := s.generatePreview(bgCtx, asset); err != nil {
            log.Printf("Failed to generate preview for asset %d: %v", asset.ID, err)
        }
    }()

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(asset)
}

func (s *Server) handleListAssets(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    status := r.URL.Query().Get("status")
    assets, err := s.store.List(r.Context(), status)
    if err != nil {
        http.Error(w, "Failed to list assets: "+err.Error(), http.StatusInternalServerError)
        return
    }
    if assets == nil {
        assets = []*Asset{}
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(assets)
}

func (s *Server) handleGetAsset(w http.ResponseWriter, r *http.Request) {
    id, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/api/assets/"))
    if err != nil {
        http.Error(w, "Invalid asset ID", http.StatusBadRequest)
        return
    }

    asset, err := s.store.Get(r.Context(), id)
    if err != nil {
        http.Error(w, "Failed to get asset: "+err.Error(), http.StatusInternalServerError)
        return
    }
    if asset == nil {
        http.Error(w, "Asset not found", http.StatusNotFound)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(asset)
}

func (s *Server) handleUpdateAsset(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPut {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    id, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/api/assets/"))
    if err != nil {
        http.Error(w, "Invalid asset ID", http.StatusBadRequest)
        return
    }

    var req struct {
        Status string `json:"status"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    validStatuses := map[string]bool{"pending": true, "approved": true, "rejected": true, "uploaded": true}
    if !validStatuses[req.Status] {
        http.Error(w, "Invalid status", http.StatusBadRequest)
        return
    }

    asset, err := s.store.Update(r.Context(), id, req.Status)
    if err != nil {
        http.Error(w, "Failed to update asset: "+err.Error(), http.StatusInternalServerError)
        return
    }
    if asset == nil {
        http.Error(w, "Asset not found", http.StatusNotFound)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(asset)
}

func (s *Server) handleStreamAsset(w http.ResponseWriter, r *http.Request) {
    // Extract ID from path like /api/assets/123/stream
    path := strings.TrimPrefix(r.URL.Path, "/api/assets/")
    path = strings.TrimSuffix(path, "/stream")
    id, err := strconv.Atoi(path)
    if err != nil {
        http.Error(w, "Invalid asset ID", http.StatusBadRequest)
        return
    }

    asset, err := s.store.Get(r.Context(), id)
    if err != nil {
        http.Error(w, "Failed to get asset: "+err.Error(), http.StatusInternalServerError)
        return
    }
    if asset == nil {
        http.Error(w, "Asset not found", http.StatusNotFound)
        return
    }

    ctx := r.Context()
    obj := s.gcsClient.Bucket(s.bucketName).Object(asset.GCSPath)
    reader, err := obj.NewReader(ctx)
    if err != nil {
        http.Error(w, "Failed to read from GCS: "+err.Error(), http.StatusInternalServerError)
        return
    }
    defer reader.Close()

    w.Header().Set("Content-Type", asset.MimeType)
    w.Header().Set("Content-Length", strconv.FormatInt(asset.Size, 10))
    io.Copy(w, reader)
}

func (s *Server) handleStreamThumbnail(w http.ResponseWriter, r *http.Request) {
    // Extract ID from path like /api/assets/123/thumbnail
    path := strings.TrimPrefix(r.URL.Path, "/api/assets/")
    path = strings.TrimSuffix(path, "/thumbnail")
    id, err := strconv.Atoi(path)
    if err != nil {
        http.Error(w, "Invalid asset ID", http.StatusBadRequest)
        return
    }

    asset, err := s.store.Get(r.Context(), id)
    if err != nil {
        http.Error(w, "Failed to get asset: "+err.Error(), http.StatusInternalServerError)
        return
    }
    if asset == nil {
        http.Error(w, "Asset not found", http.StatusNotFound)
        return
    }
    if asset.ThumbnailPath == nil {
        http.Error(w, "Thumbnail not available", http.StatusNotFound)
        return
    }

    ctx := r.Context()
    obj := s.gcsClient.Bucket(s.bucketName).Object(*asset.ThumbnailPath)
    reader, err := obj.NewReader(ctx)
    if err != nil {
        http.Error(w, "Failed to read thumbnail: "+err.Error(), http.StatusInternalServerError)
        return
    }
    defer reader.Close()

    w.Header().Set("Content-Type", "image/jpeg")
    w.Header().Set("Cache-Control", "public, max-age=86400")
    io.Copy(w, reader)
}

func (s *Server) handleStreamPreview(w http.ResponseWriter, r *http.Request) {
    // Extract ID from path like /api/assets/123/preview
    path := strings.TrimPrefix(r.URL.Path, "/api/assets/")
    path = strings.TrimSuffix(path, "/preview")
    id, err := strconv.Atoi(path)
    if err != nil {
        http.Error(w, "Invalid asset ID", http.StatusBadRequest)
        return
    }

    asset, err := s.store.Get(r.Context(), id)
    if err != nil {
        http.Error(w, "Failed to get asset: "+err.Error(), http.StatusInternalServerError)
        return
    }
    if asset == nil {
        http.Error(w, "Asset not found", http.StatusNotFound)
        return
    }
    if asset.PreviewPath == nil {
        http.Error(w, "Preview not available", http.StatusNotFound)
        return
    }

    ctx := r.Context()
    obj := s.gcsClient.Bucket(s.bucketName).Object(*asset.PreviewPath)
    attrs, err := obj.Attrs(ctx)
    if err != nil {
        http.Error(w, "Failed to get preview attributes: "+err.Error(), http.StatusInternalServerError)
        return
    }

    reader, err := obj.NewReader(ctx)
    if err != nil {
        http.Error(w, "Failed to read preview: "+err.Error(), http.StatusInternalServerError)
        return
    }
    defer reader.Close()

    w.Header().Set("Content-Type", "video/mp4")
    w.Header().Set("Content-Length", strconv.FormatInt(attrs.Size, 10))
    w.Header().Set("Cache-Control", "public, max-age=86400")
    io.Copy(w, reader)
}

func (s *Server) handleDeleteAsset(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodDelete {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    id, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/api/assets/"))
    if err != nil {
        http.Error(w, "Invalid asset ID", http.StatusBadRequest)
        return
    }

    asset, err := s.store.Get(r.Context(), id)
    if err != nil {
        http.Error(w, "Failed to get asset: "+err.Error(), http.StatusInternalServerError)
        return
    }
    if asset == nil {
        http.Error(w, "Asset not found", http.StatusNotFound)
        return
    }

    // Delete from GCS
    ctx := r.Context()
    if err := s.gcsClient.Bucket(s.bucketName).Object(asset.GCSPath).Delete(ctx); err != nil {
        log.Printf("Warning: failed to delete video from GCS: %v", err)
    }

    // Delete thumbnail from GCS if exists
    if asset.ThumbnailPath != nil {
        if err := s.gcsClient.Bucket(s.bucketName).Object(*asset.ThumbnailPath).Delete(ctx); err != nil {
            log.Printf("Warning: failed to delete thumbnail from GCS: %v", err)
        } else {
            log.Printf("Deleted thumbnail for asset %d: %s", asset.ID, *asset.ThumbnailPath)
        }
    }

    // Delete preview from GCS if exists
    if asset.PreviewPath != nil {
        if err := s.gcsClient.Bucket(s.bucketName).Object(*asset.PreviewPath).Delete(ctx); err != nil {
            log.Printf("Warning: failed to delete preview from GCS: %v", err)
        } else {
            log.Printf("Deleted preview for asset %d: %s", asset.ID, *asset.PreviewPath)
        }
    }

    if err := s.store.Delete(ctx, id); err != nil {
        http.Error(w, "Failed to delete asset: "+err.Error(), http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusNoContent)
}

// YouTube OAuth handlers

func (s *Server) handleYouTubeAuth(w http.ResponseWriter, r *http.Request) {
    if s.youtubeOAuth == nil {
        http.Error(w, "YouTube OAuth not configured", http.StatusServiceUnavailable)
        return
    }
    // AccessTypeOffline requests a refresh token
    // ApprovalForce forces consent screen to always get a fresh refresh token
    url := s.youtubeOAuth.AuthCodeURL("state-token", oauth2.AccessTypeOffline, oauth2.ApprovalForce)
    http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (s *Server) handleYouTubeCallback(w http.ResponseWriter, r *http.Request) {
    if s.youtubeOAuth == nil {
        http.Error(w, "YouTube OAuth not configured", http.StatusServiceUnavailable)
        return
    }

    code := r.URL.Query().Get("code")
    if code == "" {
        http.Error(w, "Missing authorization code", http.StatusBadRequest)
        return
    }

    token, err := s.youtubeOAuth.Exchange(r.Context(), code)
    if err != nil {
        http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
        return
    }

    if token.RefreshToken == "" {
        log.Println("Warning: No refresh token received from Google")
    } else {
        log.Println("Refresh token received successfully")
    }

    if err := s.tokenStore.Save(r.Context(), token); err != nil {
        http.Error(w, "Failed to save token: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Redirect to frontend with success message
    http.Redirect(w, r, "http://localhost:5173/?youtube=connected", http.StatusTemporaryRedirect)
}

func (s *Server) handleYouTubeStatus(w http.ResponseWriter, r *http.Request) {
    token, err := s.tokenStore.Get(r.Context())
    if err != nil {
        http.Error(w, "Failed to get token: "+err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]bool{
        "connected": token != nil,
    })
}

func (s *Server) handleYouTubeUpload(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    // Extract asset ID from path like /api/assets/123/youtube
    path := strings.TrimPrefix(r.URL.Path, "/api/assets/")
    path = strings.TrimSuffix(path, "/youtube")
    id, err := strconv.Atoi(path)
    if err != nil {
        http.Error(w, "Invalid asset ID", http.StatusBadRequest)
        return
    }

    ctx := r.Context()

    // Get the asset
    asset, err := s.store.Get(ctx, id)
    if err != nil {
        http.Error(w, "Failed to get asset: "+err.Error(), http.StatusInternalServerError)
        return
    }
    if asset == nil {
        http.Error(w, "Asset not found", http.StatusNotFound)
        return
    }

    // Check asset is approved
    if asset.Status != "approved" {
        http.Error(w, "Asset must be approved before uploading to YouTube", http.StatusBadRequest)
        return
    }

    // Get YouTube token
    token, err := s.tokenStore.Get(ctx)
    if err != nil {
        http.Error(w, "Failed to get YouTube token: "+err.Error(), http.StatusInternalServerError)
        return
    }
    if token == nil {
        http.Error(w, "YouTube not connected. Please connect your YouTube account first.", http.StatusUnauthorized)
        return
    }

    // Create YouTube client
    httpClient := s.youtubeOAuth.Client(ctx, token)
    ytService, err := youtube.NewService(ctx, option.WithHTTPClient(httpClient))
    if err != nil {
        http.Error(w, "Failed to create YouTube service: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Read file from GCS
    obj := s.gcsClient.Bucket(s.bucketName).Object(asset.GCSPath)
    reader, err := obj.NewReader(ctx)
    if err != nil {
        http.Error(w, "Failed to read from GCS: "+err.Error(), http.StatusInternalServerError)
        return
    }
    defer reader.Close()

    // Parse optional title/description from request body
    var uploadReq struct {
        Title       string `json:"title"`
        Description string `json:"description"`
    }
    json.NewDecoder(r.Body).Decode(&uploadReq)

    title := uploadReq.Title
    if title == "" {
        title = asset.Name
    }

    // Create YouTube video
    video := &youtube.Video{
        Snippet: &youtube.VideoSnippet{
            Title:       title,
            Description: uploadReq.Description,
        },
        Status: &youtube.VideoStatus{
            PrivacyStatus: "private", // Start as private for safety
        },
    }

    // Upload to YouTube using chunked upload for large files
    call := ytService.Videos.Insert([]string{"snippet", "status"}, video)
    call.Media(reader, googleapi.ChunkSize(googleapi.DefaultUploadChunkSize))

    response, err := call.Do()
    if err != nil {
        http.Error(w, "Failed to upload to YouTube: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Save YouTube video record
    ytVideo, err := s.youtubeVideoStore.Create(ctx, &YouTubeVideo{
        AssetID:       id,
        YouTubeID:     response.Id,
        Title:         title,
        PrivacyStatus: "private",
    })
    if err != nil {
        log.Printf("Failed to save YouTube video record: %v", err)
        http.Error(w, "Video uploaded to YouTube but failed to save record: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Update asset status to uploaded
    asset, err = s.store.Update(ctx, id, "uploaded")
    if err != nil {
        log.Printf("Failed to update asset status: %v", err)
        http.Error(w, "Failed to update asset status: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Save new token if it was refreshed
    newToken, err := s.youtubeOAuth.TokenSource(ctx, token).Token()
    if err == nil && newToken.AccessToken != token.AccessToken {
        s.tokenStore.Save(ctx, newToken)
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "youtube_video": ytVideo,
        "asset":         asset,
    })
}

func (s *Server) handleGetYouTubeVideo(w http.ResponseWriter, r *http.Request) {
    // Extract asset ID from path like /api/assets/123/youtube
    path := strings.TrimPrefix(r.URL.Path, "/api/assets/")
    path = strings.TrimSuffix(path, "/youtube")
    id, err := strconv.Atoi(path)
    if err != nil {
        http.Error(w, "Invalid asset ID", http.StatusBadRequest)
        return
    }

    video, err := s.youtubeVideoStore.GetByAssetID(r.Context(), id)
    if err != nil {
        http.Error(w, "Failed to get YouTube video: "+err.Error(), http.StatusInternalServerError)
        return
    }
    if video == nil {
        http.Error(w, "YouTube video not found", http.StatusNotFound)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(video)
}

func (s *Server) routes() http.Handler {
    mux := http.NewServeMux()

    // API routes
    mux.HandleFunc("/api/upload", s.handleUpload)
    mux.HandleFunc("/api/assets", s.handleListAssets)
    mux.HandleFunc("/api/assets/", func(w http.ResponseWriter, r *http.Request) {
        if strings.HasSuffix(r.URL.Path, "/stream") {
            s.handleStreamAsset(w, r)
            return
        }
        if strings.HasSuffix(r.URL.Path, "/thumbnail") {
            s.handleStreamThumbnail(w, r)
            return
        }
        if strings.HasSuffix(r.URL.Path, "/preview") {
            s.handleStreamPreview(w, r)
            return
        }
        if strings.HasSuffix(r.URL.Path, "/youtube") {
            switch r.Method {
            case http.MethodGet:
                s.handleGetYouTubeVideo(w, r)
            case http.MethodPost:
                s.handleYouTubeUpload(w, r)
            default:
                http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
            }
            return
        }
        switch r.Method {
        case http.MethodGet:
            s.handleGetAsset(w, r)
        case http.MethodPut:
            s.handleUpdateAsset(w, r)
        case http.MethodDelete:
            s.handleDeleteAsset(w, r)
        default:
            http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        }
    })

    // YouTube OAuth routes
    mux.HandleFunc("/api/auth/youtube", s.handleYouTubeAuth)
    mux.HandleFunc("/api/auth/youtube/callback", s.handleYouTubeCallback)
    mux.HandleFunc("/api/auth/youtube/status", s.handleYouTubeStatus)

    // SSE endpoint for real-time updates
    mux.HandleFunc("/api/events", s.handleSSE)

    // Health check
    mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("OK"))
    })

    return corsMiddleware(mux)
}

func getEnv(key, fallback string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return fallback
}

func main() {
    // Load .env file if present
    godotenv.Load()

    // Load config from environment
    databaseURL := getEnv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/mam_dev?sslmode=disable")
    bucketName := getEnv("GCS_BUCKET", "upload_sample_bucket")
    port := getEnv("PORT", "8080")
    ytClientID := os.Getenv("YOUTUBE_CLIENT_ID")
    ytClientSecret := os.Getenv("YOUTUBE_CLIENT_SECRET")
    encryptionKeyStr := os.Getenv("ENCRYPTION_KEY")

    // Parse encryption key (must be 32 bytes for AES-256)
    var encryptionKey []byte
    if encryptionKeyStr != "" {
        var err error
        encryptionKey, err = base64.StdEncoding.DecodeString(encryptionKeyStr)
        if err != nil {
            log.Fatalf("Invalid ENCRYPTION_KEY (must be base64 encoded): %v", err)
        }
        if len(encryptionKey) != 32 {
            log.Fatalf("ENCRYPTION_KEY must be 32 bytes (got %d)", len(encryptionKey))
        }
    } else {
        log.Fatal("ENCRYPTION_KEY is required for token encryption")
    }

    // Connect to database
    db, err := sql.Open("pgx", databaseURL)
    if err != nil {
        log.Fatalf("Failed to connect to database: %v", err)
    }
    defer db.Close()

    // Verify connection
    if err := db.Ping(); err != nil {
        log.Fatalf("Failed to ping database: %v", err)
    }
    log.Println("Connected to PostgreSQL")

    // Create server
    server, err := NewServer(db, bucketName, ytClientID, ytClientSecret, encryptionKey)
    if err != nil {
        log.Fatalf("Failed to create server: %v", err)
    }
    defer server.Close()

    if ytClientID != "" {
        log.Println("YouTube OAuth configured")
    } else {
        log.Println("YouTube OAuth not configured (set YOUTUBE_CLIENT_ID and YOUTUBE_CLIENT_SECRET)")
    }

    addr := ":" + port
    log.Printf("MAM API server starting on %s", addr)
    log.Println("Endpoints:")
    log.Println("  POST   /api/upload              - Upload media file")
    log.Println("  GET    /api/assets              - List assets (?status=pending)")
    log.Println("  GET    /api/assets/:id          - Get asset details")
    log.Println("  PUT    /api/assets/:id          - Update status")
    log.Println("  GET    /api/assets/:id/stream   - Stream original media")
    log.Println("  GET    /api/assets/:id/preview  - Stream low-res preview (MP4)")
    log.Println("  DELETE /api/assets/:id          - Delete asset")
    log.Println("  POST   /api/assets/:id/youtube  - Upload to YouTube")
    log.Println("  GET    /api/auth/youtube        - Start YouTube OAuth")
    log.Println("  GET    /api/auth/youtube/status - Check YouTube connection")

    if err := http.ListenAndServe(addr, server.routes()); err != nil {
        log.Fatalf("Server failed: %v", err)
    }
}
