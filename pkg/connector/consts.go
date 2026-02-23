package connector

// OperationType values from LINE SSE operations.
type OperationType int

const (
	OpChatUpdate     OperationType = 121
	OpChatUpdate2    OperationType = 122
	OpReadReceipt    OperationType = 55
	OpUnsendLocal    OperationType = 64
	OpUnsendRemote   OperationType = 65
	OpSendMessage    OperationType = 25
	OpReceiveMessage OperationType = 26
	OpReaction       OperationType = 140
)

// ContentType values for LINE messages.
type ContentType int

const (
	ContentText    ContentType = 0
	ContentImage   ContentType = 1
	ContentVideo   ContentType = 2
	ContentSticker ContentType = 7
	ContentFile    ContentType = 14
)

// ToType values for LINE message destinations.
type ToType int

const (
	ToUser  ToType = 0
	ToRoom  ToType = 1
	ToGroup ToType = 2
)
