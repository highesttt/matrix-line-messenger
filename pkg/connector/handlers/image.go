package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/event"

	"github.com/highesttt/matrix-line-messenger/pkg/line"
)

// ConvertImage converts a LINE image message to a Matrix image message.
func (h *Handler) ConvertImage(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI, data line.Message, decryptedBody string, relatesTo *event.RelatesTo) (*bridgev2.ConvertedMessage, error) {
	client := h.NewClient()
	oid := data.ContentMetadata["OID"]
	isPlainMedia := oid == ""

	// For plain media, the image is stored at r/talk/m/{messageID}
	if isPlainMedia {
		oid = data.ID
	}

	if oid == "" {
		return nil, nil
	}

	// Check MEDIA_CONTENT_INFO for animated flag — used for download path and Matrix message type
	metadataAnimated := false
	if mediaInfo := data.ContentMetadata["MEDIA_CONTENT_INFO"]; mediaInfo != "" {
		var info struct {
			Animated bool `json:"animated"`
		}
		if json.Unmarshal([]byte(mediaInfo), &info) == nil && info.Animated {
			metadataAnimated = true
		}
	}

	downloadImage := func(c *line.Client) ([]byte, error) {
		sid := "emi"
		if isPlainMedia {
			sid = "m"
		}
		if metadataAnimated {
			return c.DownloadOBSOriginal(oid, data.ID, sid)
		}
		if isPlainMedia {
			return c.DownloadOBSWithSID(oid, data.ID, sid)
		}
		return c.DownloadOBS(oid, data.ID)
	}

	imgData, err := downloadImage(client)

	// Refresh token if we get a 401
	if newClient, ok := h.tryRecoverClient(ctx, err); ok {
		client = newClient
		imgData, err = downloadImage(client)
	}

	if err != nil {
		h.Log.Warn().
			Err(err).
			Str("oid", oid).
			Str("msg_id", data.ID).
			Bool("plain_media", isPlainMedia).
			Msg("Failed to download image from OBS, sending placeholder")
		return &bridgev2.ConvertedMessage{
			Parts: []*bridgev2.ConvertedMessagePart{
				{
					Type: event.EventMessage,
					Content: &event.MessageEventContent{
						MsgType:   event.MsgNotice,
						Body:      "[Image unavailable — LINE media expired before it could be bridged]",
						RelatesTo: relatesTo,
					},
				},
			},
		}, nil
	}

	// Decrypt image if it has keyMaterial (E2EE)
	if decryptedBody != "" && strings.Contains(decryptedBody, "keyMaterial") {
		var decryptInfo struct {
			KeyMaterial string `json:"keyMaterial"`
			FileName    string `json:"fileName"`
		}
		if err := json.Unmarshal([]byte(decryptedBody), &decryptInfo); err == nil && decryptInfo.KeyMaterial != "" {
			decryptedImg, err := h.DecryptMedia(imgData, decryptInfo.KeyMaterial)
			if err != nil {
				h.Log.Error().Err(err).Msg("Failed to decrypt image data")
				return nil, fmt.Errorf("failed to decrypt image data: %w", err)
			}
			imgData = decryptedImg
		}
	}

	// Detect actual image format for correct MIME type
	fileName := "image.jpg"
	mimeType := "image/jpeg"
	isAnimated := false

	if h.IsAnimatedGif(imgData) {
		fileName = "image.gif"
		mimeType = "image/gif"
		isAnimated = true
	} else if len(imgData) >= 3 && string(imgData[0:3]) == "GIF" {
		fileName = "image.gif"
		mimeType = "image/gif"
		// Static GIF per data, but metadata says animated — trust metadata
		isAnimated = metadataAnimated
	} else if len(imgData) >= 8 && string(imgData[:8]) == "\x89PNG\r\n\x1a\n" {
		fileName = "image.png"
		mimeType = "image/png"
	} else if len(imgData) >= 4 && string(imgData[:4]) == "RIFF" && len(imgData) >= 12 && string(imgData[8:12]) == "WEBP" {
		fileName = "image.webp"
		mimeType = "image/webp"
	}

	// Upload to Matrix
	mxc, file, err := intent.UploadMedia(ctx, portal.MXID, imgData, fileName, mimeType)
	if err != nil {
		h.Log.Error().Err(err).Int("size_bytes", len(imgData)).Msg("Failed to upload image to Matrix")
		return nil, fmt.Errorf("failed to upload image to matrix: %w", err)
	}

	msgType := event.MsgImage
	var info *event.FileInfo
	if isAnimated {
		// Send as MsgVideo with fi.mau.gif so Beeper renders it as animated GIF
		msgType = event.MsgVideo
		info = &event.FileInfo{
			MimeType: mimeType,
			Size:     len(imgData),
			MauGIF:   true,
		}
	}

	return &bridgev2.ConvertedMessage{
		Parts: []*bridgev2.ConvertedMessagePart{
			{
				Type: event.EventMessage,
				Content: &event.MessageEventContent{
					MsgType:   msgType,
					Body:      fileName,
					URL:       mxc,
					File:      file,
					Info:      info,
					RelatesTo: relatesTo,
				},
			},
		},
	}, nil
}
