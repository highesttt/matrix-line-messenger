package handlers

import (
	"context"
	"fmt"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/event"

	"github.com/highesttt/matrix-line-messenger/pkg/line"
)

// ConvertContact converts a LINE contact share (contentType 13) to a Matrix notice.
// LINE only provides displayName and internal MID, so a vCard would be empty.
func (h *Handler) ConvertContact(data line.Message, relatesTo *event.RelatesTo) (*bridgev2.ConvertedMessage, error) {
	displayName := data.ContentMetadata["displayName"]
	if displayName == "" {
		displayName = "Unknown"
	}
	return &bridgev2.ConvertedMessage{
		Parts: []*bridgev2.ConvertedMessagePart{
			{
				Type: event.EventMessage,
				Content: &event.MessageEventContent{
					MsgType:   event.MsgNotice,
					Body:      fmt.Sprintf("LINE contact shared: %s. Open LINE to add them.", displayName),
					RelatesTo: relatesTo,
				},
			},
		},
	}, nil
}

// ConvertDeviceContact converts a device/phone contact shared via ORGCONTP metadata
// (contentType 0 with vCard data) to a Matrix file or notice.
func (h *Handler) ConvertDeviceContact(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI, data line.Message, unwrappedText string, relatesTo *event.RelatesTo) (*bridgev2.ConvertedMessage, error) {
	displayName := data.ContentMetadata["displayName"]
	if displayName == "" {
		displayName = "Unknown"
	}
	vcard := data.ContentMetadata["vCard"]
	if vcard == "" {
		// No vCard data - fall back to text notice
		body := fmt.Sprintf("Shared contact: %s", displayName)
		if unwrappedText != "" {
			body += "\n" + unwrappedText
		}
		return &bridgev2.ConvertedMessage{
			Parts: []*bridgev2.ConvertedMessagePart{
				{
					Type: event.EventMessage,
					Content: &event.MessageEventContent{
						MsgType:   event.MsgNotice,
						Body:      body,
						RelatesTo: relatesTo,
					},
				},
			},
		}, nil
	}

	fileName := displayName + ".vcf"
	vcardBytes := []byte(vcard)
	mxc, file, err := intent.UploadMedia(ctx, portal.MXID, vcardBytes, fileName, "text/vcard")
	if err != nil {
		h.Log.Warn().Err(err).Msg("Failed to upload device contact vCard")
		return &bridgev2.ConvertedMessage{
			Parts: []*bridgev2.ConvertedMessagePart{
				{
					Type: event.EventMessage,
					Content: &event.MessageEventContent{
						MsgType:   event.MsgNotice,
						Body:      fmt.Sprintf("Shared contact: %s", displayName),
						RelatesTo: relatesTo,
					},
				},
			},
		}, nil
	}

	return &bridgev2.ConvertedMessage{
		Parts: []*bridgev2.ConvertedMessagePart{
			{
				Type: event.EventMessage,
				Content: &event.MessageEventContent{
					MsgType:  event.MsgFile,
					Body:     fileName,
					URL:      mxc,
					File:     file,
					FileName: fileName,
					Info: &event.FileInfo{
						MimeType: "text/vcard",
						Size:     len(vcardBytes),
					},
					RelatesTo: relatesTo,
				},
			},
		},
	}, nil
}
