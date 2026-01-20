package line

import "encoding/json"

type ReactionParam2 struct {
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

func ParseReactionParam2(data string) (*ReactionParam2, error) {
	var p ReactionParam2
	if err := json.Unmarshal([]byte(data), &p); err != nil {
		return nil, err
	}
	return &p, nil
}
