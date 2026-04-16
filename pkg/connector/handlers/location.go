package handlers

import (
	"fmt"
	"strings"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/event"

	"github.com/highesttt/matrix-line-messenger/pkg/line"
)

// ConvertLocation converts a LINE location message to a Matrix location message.
func (h *Handler) ConvertLocation(data line.Message, relatesTo *event.RelatesTo) (*bridgev2.ConvertedMessage, error) {
	if data.Location == nil {
		return &bridgev2.ConvertedMessage{
			Parts: []*bridgev2.ConvertedMessagePart{
				{
					Type: event.EventMessage,
					Content: &event.MessageEventContent{
						MsgType: event.MsgNotice,
						Body:    "[Location unavailable]",
					},
				},
			},
		}, nil
	}

	geoURI := fmt.Sprintf("geo:%.6f,%.6f", data.Location.Latitude, data.Location.Longitude)
	mapsURL := fmt.Sprintf("https://maps.google.com/maps?q=%.6f%%2C%.6f", data.Location.Latitude, data.Location.Longitude)

	var bodyParts []string
	if data.Location.Title != "" {
		bodyParts = append(bodyParts, data.Location.Title)
	}
	if data.Location.Address != "" {
		bodyParts = append(bodyParts, data.Location.Address)
	}
	bodyParts = append(bodyParts, mapsURL)
	body := strings.Join(bodyParts, "\n")

	return &bridgev2.ConvertedMessage{
		Parts: []*bridgev2.ConvertedMessagePart{
			{
				Type: event.EventMessage,
				Content: &event.MessageEventContent{
					MsgType:   event.MsgLocation,
					Body:      body,
					GeoURI:    geoURI,
					RelatesTo: relatesTo,
				},
			},
		},
	}, nil
}
