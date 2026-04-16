package handlers

import (
	"regexp"
	"strings"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// ConvertText converts a LINE text message to a Matrix text message, including link previews.
func (h *Handler) ConvertText(unwrappedText string, relatesTo *event.RelatesTo) (*bridgev2.ConvertedMessage, error) {
	client := h.NewClient()

	content := &event.MessageEventContent{
		MsgType:   event.MsgText,
		Body:      unwrappedText,
		RelatesTo: relatesTo,
	}

	urlRegex := regexp.MustCompile(`(https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(/[^\s]*)?`)
	if match := urlRegex.FindString(unwrappedText); match != "" {
		match = strings.TrimRight(match, ".,;:!?")
		requestURL := match
		if !strings.HasPrefix(match, "http") {
			requestURL = "https://" + match
		}
		if info, err := client.GetPageInfo(requestURL); err == nil {
			preview := &event.BeeperLinkPreview{
				MatchedURL: match,
				LinkPreview: event.LinkPreview{
					Title:        info.Title,
					Description:  info.Summary,
					CanonicalURL: info.Domain,
				},
			}
			if info.Image != "" && info.Obs.CDN != "" {
				preview.ImageURL = id.ContentURIString(info.Obs.CDN + info.Image)
			}
			content.BeeperLinkPreviews = []*event.BeeperLinkPreview{preview}
		}
	}

	return &bridgev2.ConvertedMessage{
		Parts: []*bridgev2.ConvertedMessagePart{
			{
				Type:    event.EventMessage,
				Content: content,
			},
		},
	}, nil
}
