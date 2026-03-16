package connector

import (
	"errors"

	"github.com/highesttt/matrix-line-messenger/pkg/line"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/status"
	"maunium.net/go/mautrix/event"
)

func wrapLetterSealingSendError(portalMid string, isGroup bool, err error) error {
	if err == nil {
		return nil
	}
	if isGroup && line.IsNoUsableE2EEGroupKey(err) {
		message := "This LINE group can't be bridged because it doesn't expose usable Letter Sealing keys. At least one participant likely has Letter Sealing disabled."
		internalMessage := "line group can't be bridged because it doesn't expose usable letter sealing keys"
		return bridgev2.MessageStatus{
			Step:           status.MsgStepRemote,
			Status:         event.MessageStatusFail,
			ErrorReason:    event.MessageStatusUnsupported,
			InternalError:  errors.New(internalMessage),
			Message:        message,
			ErrorAsMessage: true,
			SendNotice:     true,
			IsCertain:      true,
		}
	}
	if !isGroup && line.IsNoUsableE2EEPublicKey(err) {
		message := "This LINE chat can't be bridged because the recipient doesn't expose a usable Letter Sealing key. They likely have Letter Sealing disabled."
		internalMessage := "line chat can't be bridged because the recipient doesn't expose a usable letter sealing key"
		return bridgev2.MessageStatus{
			Step:           status.MsgStepRemote,
			Status:         event.MessageStatusFail,
			ErrorReason:    event.MessageStatusUnsupported,
			InternalError:  errors.New(internalMessage),
			Message:        message,
			ErrorAsMessage: true,
			SendNotice:     true,
			IsCertain:      true,
		}
	}
	return err
}
