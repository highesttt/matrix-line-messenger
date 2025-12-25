package connector

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.mau.fi/util/configupgrade"
	"go.mau.fi/util/exhttp"
	"go.mau.fi/util/requestlog"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/bridgev2/status"

	"github.com/rs/zerolog/hlog"

	"github.com/highesttt/mautrix-line-messenger/pkg/e2ee"
	"github.com/highesttt/mautrix-line-messenger/pkg/line"
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
	server.GetRouter().Handle("/_line/", exhttp.ApplyMiddleware(
		router,
		exhttp.StripPrefix("/_line"),
		hlog.NewHandler(lc.br.Log.With().Str("component", "line webhooks").Logger()),
		requestlog.AccessLogger(requestlog.Options{TrustXForwardedFor: true}),
	))
	return nil
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
		NetworkIcon:      "https://www.google.com/s2/favicons?domain=line.me&sz=256",
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
	AccessToken       string            `json:"access_token"`
	RefreshToken      string            `json:"refresh_token,omitempty"`
	Email             string            `json:"email,omitempty"`
	Password          string            `json:"password,omitempty"`
	Mid               string            `json:"mid,omitempty"`
	EncryptedKeyChain string            `json:"encrypted_key_chain,omitempty"`
	E2EEPublicKey     string            `json:"e2ee_public_key,omitempty"`
	E2EEVersion       string            `json:"e2ee_version,omitempty"`
	E2EEKeyID         string            `json:"e2ee_key_id,omitempty"`
	ExportedKeyMap    map[string]string `json:"exported_key_map,omitempty"`
}

func (lc *LineConnector) LoadUserLogin(ctx context.Context, login *bridgev2.UserLogin) error {
	meta := login.Metadata.(*UserLoginMetadata)
	login.Client = &LineClient{
		UserLogin:    login,
		AccessToken:  meta.AccessToken,
		RefreshToken: meta.RefreshToken,
		Mid:          meta.Mid,
		HTTPClient:   &http.Client{Timeout: 10 * time.Second},
	}
	return nil
}

func (lc *LineConnector) GetLoginFlows() []bridgev2.LoginFlow {
	return []bridgev2.LoginFlow{{
		Name:        "Login",
		Description: "Login with your LINE Email and Password",
	}}
}

func (lc *LineConnector) CreateLogin(ctx context.Context, user *bridgev2.User, flowID string) (bridgev2.LoginProcess, error) {
	return &LineEmailLogin{User: user}, nil
}

type LineEmailLogin struct {
	User     *bridgev2.User
	Email    string
	Password string
	Verifier string

	pollResult chan *line.LoginResult
	pollErr    chan error
	polling    bool
	mu         sync.Mutex
}

var _ bridgev2.LoginProcessUserInput = (*LineEmailLogin)(nil)

func (ll *LineEmailLogin) Start(ctx context.Context) (*bridgev2.LoginStep, error) {
	return &bridgev2.LoginStep{
		Type:         bridgev2.LoginStepTypeUserInput,
		StepID:       "fi.mau.line.enter_creds",
		Instructions: "Please enter your LINE email and password.",
		UserInputParams: &bridgev2.LoginUserInputParams{
			Fields: []bridgev2.LoginInputDataField{
				{
					Type: bridgev2.LoginInputFieldTypeUsername,
					ID:   "email",
					Name: "Email",
				},
				{
					Type: bridgev2.LoginInputFieldTypePassword,
					ID:   "password",
					Name: "Password",
				},
			},
		},
	}, nil
}

func (ll *LineEmailLogin) SubmitUserInput(ctx context.Context, input map[string]string) (*bridgev2.LoginStep, error) {
	if ll.Verifier != "" {
		// User clicked "Continue" on the PIN screen. Wait for the background polling to finish.
		select {
		case res := <-ll.pollResult:
			if res.AuthToken != "" {
				return ll.finishLogin(ctx, res)
			}
		case err := <-ll.pollErr:
			return nil, fmt.Errorf("verification failed: %w", err)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("unexpected end of polling")
	}

	if input["email"] != "" {
		ll.Email = input["email"]
		ll.Password = input["password"]
	}

	if ll.Email == "" || ll.Password == "" {
		return nil, fmt.Errorf("email and password are required")
	}

	client := line.NewClient("")
	res, err := client.Login(ll.Email, ll.Password)
	if err != nil {
		return nil, fmt.Errorf("login failed: %w", err)
	}

	if res.AuthToken != "" {
		return ll.finishLogin(ctx, res)
	}

	if (res.Type == 3 || res.Type == 0) && res.Verifier != "" {
		ll.Verifier = res.Verifier
		instructions := "A verification request has been sent to your LINE device."
		pin := res.Pin
		if res.PinCode != "" {
			pin = res.PinCode
		}
		if pin != "" {
			instructions += fmt.Sprintf("\n\n**Please enter this PIN code on your mobile device: %s**", pin)
		}
		instructions += "\n\nAfter entering the code (or approving), click 'Continue' to finish login."

		// Start polling in background immediately so it's running while the user enters the PIN
		ll.mu.Lock()
		ll.polling = true
		ll.pollResult = make(chan *line.LoginResult, 1)
		ll.pollErr = make(chan error, 1)
		go func() {
			client := line.NewClient("")
			res, err := client.WaitForLogin(ll.Verifier)
			if err != nil {
				ll.pollErr <- err
			} else {
				ll.pollResult <- res
			}
		}()
		ll.mu.Unlock()

		return &bridgev2.LoginStep{
			Type:         bridgev2.LoginStepTypeUserInput,
			StepID:       "fi.mau.line.wait_verification",
			Instructions: instructions,
			UserInputParams: &bridgev2.LoginUserInputParams{
				Fields: []bridgev2.LoginInputDataField{
					{
						Type:        bridgev2.LoginInputFieldTypePassword, // hidden field just to have a submit button
						ID:          "dummy",
						Name:        "Action",
						Description: "Press Enter/Continue when done",
					},
				},
			},
		}, nil
	}

	if res.Certificate != "" {
		return &bridgev2.LoginStep{
			Type:         bridgev2.LoginStepTypeUserInput,
			StepID:       "fi.mau.line.enter_pin",
			Instructions: fmt.Sprintf("Please open the LINE app on your mobile device and enter this PIN code: **%s**\n\nAfter entering the code, click 'Continue' below.", res.Certificate),
			UserInputParams: &bridgev2.LoginUserInputParams{
				Fields: []bridgev2.LoginInputDataField{
					{
						Type:        bridgev2.LoginInputFieldTypePassword, // hidden dummy field
						ID:          "dummy",
						Name:        "Hidden",
						Description: "Press Enter to continue",
					},
				},
			},
		}, nil
	}

	return nil, fmt.Errorf("login incomplete but no PIN found in response (Type: %d, Msg: %s)", res.Type, res.Message)
}

func (ll *LineEmailLogin) finishLogin(ctx context.Context, res *line.LoginResult) (*bridgev2.LoginStep, error) {
	if res == nil {
		return nil, fmt.Errorf("login result missing")
	}

	token := res.AuthToken
	refreshToken := ""
	if token == "" && res.TokenV3IssueResult != nil {
		token = res.TokenV3IssueResult.AccessToken
		refreshToken = res.TokenV3IssueResult.RefreshToken
	}
	if token == "" {
		return nil, fmt.Errorf("missing access token in login result")
	}

	client := line.NewClient(token)
	profile, err := client.GetProfile()
	if err != nil {
		return nil, fmt.Errorf("failed to verify token: %w", err)
	}

	displayName := profile.DisplayName
	if displayName == "" {
		displayName = "LINE User"
	}

	meta := &UserLoginMetadata{AccessToken: token, RefreshToken: refreshToken, Email: ll.Email, Password: ll.Password, Mid: res.Mid}
	if res.EncryptedKeyChain != "" && res.E2EEPublicKey != "" {
		meta.EncryptedKeyChain = res.EncryptedKeyChain
		meta.E2EEPublicKey = res.E2EEPublicKey
		meta.E2EEVersion = res.E2EEVersion
		meta.E2EEKeyID = res.E2EEKeyID
		if mgr, err := e2ee.NewManager(); err == nil {
			if ei3, err := client.GetEncryptedIdentityV3(); err == nil {
				if err := mgr.InitStorage(ei3.WrappedNonce, ei3.KDFParameter1, ei3.KDFParameter2); err == nil {
					if exported, err := mgr.InitFromLoginKeyChain(res.E2EEPublicKey, res.EncryptedKeyChain); err == nil {
						meta.ExportedKeyMap = exported
						_ = mgr.SaveSecureDataToFile(string(ll.User.MXID), map[string]any{"exportedKeyMap": exported})
					}
				}
			}
		}
	}

	detectedLineID := networkid.UserLoginID(profile.Mid)

	ul, err := ll.User.NewLogin(ctx, &database.UserLogin{
		ID:         detectedLineID,
		RemoteName: displayName,
		Metadata:   meta,
	}, &bridgev2.NewLoginParams{
		LoadUserLogin: func(ctx context.Context, login *bridgev2.UserLogin) error {
			login.Client = &LineClient{
				UserLogin:    login,
				AccessToken:  token,
				RefreshToken: refreshToken,
				HTTPClient:   &http.Client{Timeout: 10 * time.Second},
			}
			return nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create user login: %w", err)
	}

	go ul.Client.Connect(context.Background())
	ul.BridgeState.Send(status.BridgeState{StateEvent: status.StateConnected})

	return &bridgev2.LoginStep{
		Type:           bridgev2.LoginStepTypeComplete,
		StepID:         "fi.mau.line.complete",
		Instructions:   "Successfully logged in",
		CompleteParams: &bridgev2.LoginCompleteParams{UserLoginID: ul.ID, UserLogin: ul},
	}, nil
}

func (ll *LineEmailLogin) Cancel() {}
