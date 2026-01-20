package line

import "encoding/json"

type ReactionPayload struct {
	ChatMid string          `json:"chatMid"`
	Curr    *ReactionDetail `json:"curr,omitempty"`
}

type ReactionDetail struct {
	PaidReactionType *PaidReactionType `json:"paidReactionType,omitempty"`
}

type PaidReactionType struct {
	ProductID    string `json:"productId"`
	EmojiID      string `json:"emojiId"`
	ResourceType int    `json:"resourceType"`
	Version      int    `json:"version"`
}

func ParseReactionParam2(data string) (*ReactionPayload, error) {
	var p ReactionPayload
	if err := json.Unmarshal([]byte(data), &p); err != nil {
		return nil, err
	}
	return &p, nil
}
