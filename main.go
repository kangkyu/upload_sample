package main

import (
    "context"
    "fmt"
    "io"
    "os"
    "cloud.google.com/go/storage"
)

func uploadFile(bucketName, objectName, filePath string) error {
    ctx := context.Background()
    client, err := storage.NewClient(ctx)
    if err != nil {
        return fmt.Errorf("storage.NewClient: %v", err)
    }
    defer client.Close()

    f, err := os.Open(filePath)
    if err != nil {
        return fmt.Errorf("os.Open: %v", err)
    }
    defer f.Close()

    wc := client.Bucket(bucketName).Object(objectName).NewWriter(ctx)
    if _, err = io.Copy(wc, f); err != nil {
        return fmt.Errorf("io.Copy: %v", err)
    }
    if err := wc.Close(); err != nil {
        return fmt.Errorf("Writer.Close: %v", err)
    }
    fmt.Printf("Uploaded %s to bucket %s\n", objectName, bucketName)
    return nil
}

func main() {
    bucketName := "upload_sample_bucket"
    objectName := "screen-recording-object"
    filePath := "screen-recording.mov"

    if err := uploadFile(bucketName, objectName, filePath); err != nil {
        fmt.Println("Error uploading file:", err)
    }
}
