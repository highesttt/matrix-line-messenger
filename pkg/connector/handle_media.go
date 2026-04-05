package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/event"

	"github.com/highesttt/matrix-line-messenger/pkg/line"
)

// mediaUnavailablePlaceholder returns a notice when media couldn't be downloaded from LINE.
func mediaUnavailablePlaceholder(mediaType string, relatesTo *event.RelatesTo) *bridgev2.ConvertedMessage {
	return &bridgev2.ConvertedMessage{
		Parts: []*bridgev2.ConvertedMessagePart{
			{
				Type: event.EventMessage,
				Content: &event.MessageEventContent{
					MsgType:   event.MsgNotice,
					Body:      fmt.Sprintf("[%s unavailable — LINE media expired before it could be bridged]", mediaType),
					RelatesTo: relatesTo,
				},
			},
		},
	}
}

// decryptMediaData decrypts media using key material from the E2EE body payload
// (keyMaterial field) or the ENC_KM content metadata field.
// Returns data unchanged if no key is available.
func (lc *LineClient) decryptMediaData(data []byte, decryptedBody string, contentMetadata map[string]string) ([]byte, error) {
	if decryptedBody != "" && strings.Contains(decryptedBody, "keyMaterial") {
		var info struct {
			KeyMaterial string `json:"keyMaterial"`
		}
		if err := json.Unmarshal([]byte(decryptedBody), &info); err == nil && info.KeyMaterial != "" {
			return lc.decryptImageData(data, info.KeyMaterial)
		}
	}
	if encKM := contentMetadata["ENC_KM"]; encKM != "" && len(data) > 32 {
		return lc.decryptImageData(data, encKM)
	}
	return data, nil
}

// resolveReplyRelatesTo looks up the Matrix event ID for a replied-to LINE message.
func (lc *LineClient) resolveReplyRelatesTo(ctx context.Context, data *line.Message) *event.RelatesTo {
	if data == nil {
		return nil
	}

	relatedID := data.RelatedMessageID
	if relatedID == "" && data.ContentMetadata != nil {
		relatedID = data.ContentMetadata["message_relation_server_message_id"]
	}

	if relatedID == "" {
		return nil
	}

	if data.MessageRelationType != 0 && data.MessageRelationType != 3 {
		return nil
	}

	dbMsg, err := lc.UserLogin.Bridge.DB.Message.GetPartByID(ctx, lc.UserLogin.ID, networkid.MessageID(relatedID), "")
	if err != nil {
		lc.UserLogin.Bridge.Log.Debug().Err(err).Str("related_msg_id", relatedID).Msg("Failed to lookup reply target")
		return nil
	}
	if dbMsg == nil || dbMsg.MXID == "" {
		lc.UserLogin.Bridge.Log.Debug().Str("related_msg_id", relatedID).Msg("No Matrix event found for reply target")
		return nil
	}

	return &event.RelatesTo{InReplyTo: &event.InReplyTo{EventID: dbMsg.MXID}}
}
