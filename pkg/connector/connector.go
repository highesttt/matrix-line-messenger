package connector

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/highesttt/mautrix-line-messenger/pkg/line"
	"github.com/rs/zerolog/hlog"
	"go.mau.fi/util/configupgrade"
	"go.mau.fi/util/exhttp"
	"go.mau.fi/util/requestlog"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
)

type LineConnector struct {
	br *bridgev2.Bridge
}

var _ bridgev2.NetworkConnector = (*LineConnector)(nil)

func (lc *LineConnector) Init(bridge *bridgev2.Bridge) {
	lc.br = bridge
}

func (lc *LineConnector) Start(ctx context.Context) error {
	server, ok := lc.br.Matrix.(bridgev2.MatrixConnectorWithServer)
	if !ok {
		return fmt.Errorf("matrix connector does not implement MatrixConnectorWithServer")
	} else if server.GetPublicAddress() == "" {
		return fmt.Errorf("public address of bridge not configured")
	}
	router := http.NewServeMux()
	router.HandleFunc("POST /{loginID}/receive", lc.ReceiveMessage)
	server.GetRouter().Handle("/_line/", exhttp.ApplyMiddleware(
		router,
		exhttp.StripPrefix("/_line"),
		hlog.NewHandler(lc.br.Log.With().Str("component", "line webhooks").Logger()),
		requestlog.AccessLogger(requestlog.Options{TrustXForwardedFor: true}),
	))
	return nil
}

func (lc *LineConnector) ReceiveMessage(w http.ResponseWriter, r *http.Request) {
	sig := r.Header.Get("X-Line-Signature")
	if sig == "" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("Missing signature header\n"))
		return
	}

	loginID := r.PathValue("loginID")
	login := lc.br.GetCachedUserLoginByID(networkid.UserLoginID(loginID))
	if login == nil {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Unrecognized login ID in request path\n"))
		return
	}
	client := login.Client.(*LineClient)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !client.ValidateSignature(body, sig) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Invalid signature\n"))
		return
	}

	if err := client.HandleWebhook(r.Context(), body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("Failed to handle webhook\n"))
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (lc *LineConnector) GetBridgeInfoVersion() (info, capabilities int) {
	return 1, 1
}

func (lc *LineConnector) GetCapabilities() *bridgev2.NetworkGeneralCapabilities {
	return &bridgev2.NetworkGeneralCapabilities{}
}

func (lc *LineConnector) GetName() bridgev2.BridgeName {
	return bridgev2.BridgeName{
		DisplayName:      "LINE",
		NetworkURL:       "https://line.me",
		NetworkIcon:      "mxc://maunium.net/FYuKJHaCrSeSpvBJfHwgYylP",
		NetworkID:        "line",
		BeeperBridgeType: "github.com/highesttt/mautrix-line-messenger",
		DefaultPort:      29322,
	}
}

func (lc *LineConnector) GetConfig() (example string, data any, upgrader configupgrade.Upgrader) {
	return "", nil, nil
}

func (lc *LineConnector) GetDBMetaTypes() database.MetaTypes {
	return database.MetaTypes{
		Portal:   nil,
		Ghost:    nil,
		Message:  nil,
		Reaction: nil,
		UserLogin: func() any {
			return &UserLoginMetadata{}
		},
	}
}

type UserLoginMetadata struct {
	AccessToken string `json:"access_token"`
}

func (lc *LineConnector) LoadUserLogin(ctx context.Context, login *bridgev2.UserLogin) error {
	meta := login.Metadata.(*UserLoginMetadata)
	login.Client = &LineClient{
		UserLogin:   login,
		AccessToken: meta.AccessToken,
		HTTPClient:  &http.Client{Timeout: 10 * time.Second},
	}
	return nil
}

func (lc *LineConnector) GetLoginFlows() []bridgev2.LoginFlow {
	return []bridgev2.LoginFlow{{
		Name:        "Auth Token",
		Description: "Enter your LINE Auth Token (x-line-access header)",
		ID:          "auth-token",
	}}
}

func (lc *LineConnector) CreateLogin(ctx context.Context, user *bridgev2.User, flowID string) (bridgev2.LoginProcess, error) {
	switch flowID {
	case "auth-token":
		return &LineLogin{User: user}, nil
	default:
		return nil, fmt.Errorf("unknown login flow ID")
	}
}

type LineLogin struct {
	User *bridgev2.User
}

var _ bridgev2.LoginProcessUserInput = (*LineLogin)(nil)

func (ll *LineLogin) Start(ctx context.Context) (*bridgev2.LoginStep, error) {
	return &bridgev2.LoginStep{
		Type:         bridgev2.LoginStepTypeUserInput,
		StepID:       "fi.mau.line.enter_token",
		Instructions: "Please extract the 'x-line-access' header from a logged-in LINE Chrome extension session.",
		UserInputParams: &bridgev2.LoginUserInputParams{
			Fields: []bridgev2.LoginInputDataField{
				{
					Type:        bridgev2.LoginInputFieldTypePassword,
					ID:          "token",
					Name:        "Auth Token",
					Description: "x-line-access header value",
				},
			},
		},
	}, nil
}
func (ll *LineLogin) SubmitUserInput(ctx context.Context, input map[string]string) (*bridgev2.LoginStep, error) {
	token := input["token"]
	if token == "" {
		return nil, fmt.Errorf("token is empty")
	}

	// Verify the token works by fetching profile
	client := line.NewClient(token)
	// TODO: Parse profile to get actual Line ID & Username
	_, err := client.GetProfile()
	if err != nil {
		return nil, fmt.Errorf("failed to verify token: %w", err)
	}

	// Placeholder ID: will be replaced when getProfile is properly parsed
	detectedLineID := networkid.UserLoginID("line_user_" + fmt.Sprint(time.Now().Unix()))

	ul, err := ll.User.NewLogin(ctx, &database.UserLogin{
		// TODO: get actual Line ID & Username when profile parsing is implemented
		ID:         detectedLineID,
		RemoteName: "LINE User",
		Metadata: &UserLoginMetadata{
			AccessToken: token,
		},
	}, &bridgev2.NewLoginParams{
		LoadUserLogin: func(ctx context.Context, login *bridgev2.UserLogin) error {
			login.Client = &LineClient{
				UserLogin:   login,
				AccessToken: token,
				HTTPClient:  &http.Client{Timeout: 10 * time.Second},
			}
			return nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create user login: %w", err)
	}

	go ul.Client.Connect(context.Background())

	return &bridgev2.LoginStep{
		Type:           bridgev2.LoginStepTypeComplete,
		StepID:         "fi.mau.line.complete",
		Instructions:   "Successfully logged in",
		CompleteParams: &bridgev2.LoginCompleteParams{UserLoginID: ul.ID, UserLogin: ul},
	}, nil
}

func (ll *LineLogin) Cancel() {}
