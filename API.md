# MAM Backend API Documentation

Base URL: `http://localhost:8080`

## Overview

Media Asset Management (MAM) API for uploading, reviewing, and managing video/audio files. Files are stored in Google Cloud Storage. The API supports CORS for web and mobile clients.

## Data Models

### Asset

```json
{
  "id": 1,
  "name": "video.mp4",
  "size": 15728640,
  "mime_type": "video/mp4",
  "status": "pending",
  "gcs_path": "uploads/1234567890_video.mp4",
  "created_at": "2026-01-02T10:30:00Z",
  "updated_at": "2026-01-02T10:30:00Z"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `id` | integer | Unique identifier |
| `name` | string | Original filename |
| `size` | integer | File size in bytes |
| `mime_type` | string | MIME type (e.g., `video/mp4`, `audio/mpeg`) |
| `status` | string | One of: `pending`, `approved`, `rejected`, `uploaded` |
| `gcs_path` | string | Path in GCS bucket |
| `created_at` | string | ISO 8601 timestamp |
| `updated_at` | string | ISO 8601 timestamp |

### Asset Status Flow

```
pending -> approved -> uploaded
        -> rejected
```

- `pending`: Newly uploaded, awaiting review
- `approved`: Reviewed and approved for YouTube upload
- `rejected`: Reviewed and rejected
- `uploaded`: Successfully uploaded to YouTube

## Supported Media Types

### Video
- `.mp4` (video/mp4)
- `.mov` (video/quicktime)
- `.avi` (video/x-msvideo)
- `.mkv` (video/x-matroska)
- `.webm` (video/webm)

### Audio
- `.mp3` (audio/mpeg)
- `.wav` (audio/wav)
- `.aac` (audio/aac)
- `.flac` (audio/flac)
- `.m4a` (audio/mp4)

---

## Endpoints

### Health Check

Check if the server is running.

```
GET /health
```

**Response:** `200 OK`
```
OK
```

---

### Upload File

Upload a media file for review.

```
POST /api/upload
```

**Content-Type:** `multipart/form-data`

**Form Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `file` | file | Yes | Video or audio file (max 500MB) |

**Success Response:** `201 Created`
```json
{
  "id": 1,
  "name": "my-video.mp4",
  "size": 15728640,
  "mime_type": "video/mp4",
  "status": "pending",
  "gcs_path": "uploads/1735820400000000000_my-video.mp4",
  "created_at": "2026-01-02T10:30:00Z",
  "updated_at": "2026-01-02T10:30:00Z"
}
```

**Error Responses:**

| Status | Description |
|--------|-------------|
| `400 Bad Request` | Missing file, invalid file type, or parse error |
| `405 Method Not Allowed` | Not a POST request |
| `500 Internal Server Error` | GCS upload failed |

**Example (curl):**
```bash
curl -X POST \
  -F "file=@/path/to/video.mp4" \
  http://localhost:8080/api/upload
```

**Example (JavaScript fetch):**
```javascript
const formData = new FormData();
formData.append('file', fileInput.files[0]);

const response = await fetch('http://localhost:8080/api/upload', {
  method: 'POST',
  body: formData
});
const asset = await response.json();
```

---

### List Assets

Get all assets, optionally filtered by status.

```
GET /api/assets
GET /api/assets?status=pending
```

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `status` | string | No | Filter by status: `pending`, `approved`, `rejected`, `uploaded` |

**Success Response:** `200 OK`
```json
[
  {
    "id": 1,
    "name": "video1.mp4",
    "size": 15728640,
    "mime_type": "video/mp4",
    "status": "pending",
    "gcs_path": "uploads/1735820400000000000_video1.mp4",
    "created_at": "2026-01-02T10:30:00Z",
    "updated_at": "2026-01-02T10:30:00Z"
  },
  {
    "id": 2,
    "name": "audio1.mp3",
    "size": 5242880,
    "mime_type": "audio/mpeg",
    "status": "approved",
    "gcs_path": "uploads/1735820500000000000_audio1.mp3",
    "created_at": "2026-01-02T10:35:00Z",
    "updated_at": "2026-01-02T10:40:00Z"
  }
]
```

Returns empty array `[]` if no assets match.

**Example (JavaScript fetch):**
```javascript
// Get all assets
const response = await fetch('http://localhost:8080/api/assets');
const assets = await response.json();

// Get only pending assets
const pending = await fetch('http://localhost:8080/api/assets?status=pending');
const pendingAssets = await pending.json();
```

---

### Get Single Asset

Get details of a specific asset.

```
GET /api/assets/:id
```

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | integer | Asset ID |

**Success Response:** `200 OK`
```json
{
  "id": 1,
  "name": "video.mp4",
  "size": 15728640,
  "mime_type": "video/mp4",
  "status": "pending",
  "gcs_path": "uploads/1735820400000000000_video.mp4",
  "created_at": "2026-01-02T10:30:00Z",
  "updated_at": "2026-01-02T10:30:00Z"
}
```

**Error Responses:**

| Status | Description |
|--------|-------------|
| `400 Bad Request` | Invalid asset ID (not a number) |
| `404 Not Found` | Asset does not exist |

**Example (JavaScript fetch):**
```javascript
const response = await fetch('http://localhost:8080/api/assets/1');
if (response.ok) {
  const asset = await response.json();
}
```

---

### Update Asset Status

Update the review status of an asset.

```
PUT /api/assets/:id
```

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | integer | Asset ID |

**Content-Type:** `application/json`

**Request Body:**
```json
{
  "status": "approved"
}
```

| Field | Type | Required | Values |
|-------|------|----------|--------|
| `status` | string | Yes | `pending`, `approved`, `rejected`, `uploaded` |

**Success Response:** `200 OK`
```json
{
  "id": 1,
  "name": "video.mp4",
  "size": 15728640,
  "mime_type": "video/mp4",
  "status": "approved",
  "gcs_path": "uploads/1735820400000000000_video.mp4",
  "created_at": "2026-01-02T10:30:00Z",
  "updated_at": "2026-01-02T10:45:00Z"
}
```

**Error Responses:**

| Status | Description |
|--------|-------------|
| `400 Bad Request` | Invalid asset ID, invalid JSON, or invalid status value |
| `404 Not Found` | Asset does not exist |
| `405 Method Not Allowed` | Not a PUT request |

**Example (JavaScript fetch):**
```javascript
const response = await fetch('http://localhost:8080/api/assets/1', {
  method: 'PUT',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ status: 'approved' })
});
const updatedAsset = await response.json();
```

---

### Stream Asset

Stream the media file for preview playback. Use this URL as the `src` for HTML5 `<video>` or `<audio>` elements.

```
GET /api/assets/:id/stream
```

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | integer | Asset ID |

**Success Response:** `200 OK`
- **Content-Type:** Asset's MIME type (e.g., `video/mp4`)
- **Content-Length:** File size in bytes
- **Body:** Binary file stream

**Error Responses:**

| Status | Description |
|--------|-------------|
| `400 Bad Request` | Invalid asset ID |
| `404 Not Found` | Asset does not exist |
| `500 Internal Server Error` | Failed to read from GCS |

**Example (React video player):**
```jsx
function VideoPlayer({ assetId }) {
  return (
    <video controls width="100%">
      <source
        src={`http://localhost:8080/api/assets/${assetId}/stream`}
        type="video/mp4"
      />
    </video>
  );
}
```

**Example (React audio player):**
```jsx
function AudioPlayer({ assetId }) {
  return (
    <audio controls>
      <source
        src={`http://localhost:8080/api/assets/${assetId}/stream`}
        type="audio/mpeg"
      />
    </audio>
  );
}
```

---

### Delete Asset

Delete an asset and its file from GCS.

```
DELETE /api/assets/:id
```

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | integer | Asset ID |

**Success Response:** `204 No Content`

**Error Responses:**

| Status | Description |
|--------|-------------|
| `400 Bad Request` | Invalid asset ID |
| `404 Not Found` | Asset does not exist |
| `405 Method Not Allowed` | Not a DELETE request |

**Example (JavaScript fetch):**
```javascript
const response = await fetch('http://localhost:8080/api/assets/1', {
  method: 'DELETE'
});
if (response.status === 204) {
  console.log('Asset deleted');
}
```

---

## CORS

The API includes CORS headers for cross-origin requests:

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: Content-Type, Authorization
```

Preflight `OPTIONS` requests return `200 OK`.

---

## Error Response Format

Error responses are plain text:

```
HTTP/1.1 400 Bad Request
Content-Type: text/plain; charset=utf-8

Only video/audio files are allowed
```

---

## Frontend Integration Notes

### React Web App

1. **Upload Component**
   - Use `<input type="file" accept="video/*,audio/*">` for file selection
   - Submit via `FormData` to `POST /api/upload`
   - Show upload progress if needed

2. **Asset List Component**
   - Fetch from `GET /api/assets` or `GET /api/assets?status=pending`
   - Display as table/grid with name, size, status, actions

3. **Review Component**
   - Stream preview via `GET /api/assets/:id/stream` as video/audio src
   - Approve/Reject buttons call `PUT /api/assets/:id`

4. **File Size Display**
   - Size is in bytes; convert to human-readable (KB/MB/GB)

### Kotlin Android App

1. **Use Retrofit or Ktor** for API calls
2. **ExoPlayer** for video/audio streaming from `/api/assets/:id/stream`
3. **Multipart upload** for file uploads

---

## Running the Server

```bash
# Build
go build -o mam-server .

# Run (requires GCS credentials)
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/credentials.json
./mam-server

# Server starts on :8080
```

---

## Future Endpoints (Planned)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/assets/:id/youtube` | POST | Upload approved asset to YouTube |
| `/api/auth/login` | POST | User authentication |
| `/api/users` | GET | List users |
