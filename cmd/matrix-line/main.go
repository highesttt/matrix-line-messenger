package main

import (
	"fmt"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/commands"
	"maunium.net/go/mautrix/bridgev2/matrix/mxmain"

	"github.com/highesttt/matrix-line-messenger/pkg/connector"
)

// Information to find out exactly which commit the bridge was built from.
// These are filled at build time with the -X linker flag.
var (
	Tag       = "unknown"
	Commit    = "unknown"
	BuildTime = "unknown"
)

var cmdSyncContacts = &commands.FullHandler{
	Func: fnSyncContacts,
	Name: "sync-contacts",
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionChats,
		Description: "Sync your LINE contacts to Matrix (creates ghost users for all friends)",
	},
	RequiresLogin: true,
}

func fnSyncContacts(ce *commands.Event) {
	login := ce.User.GetDefaultLogin()
	if login == nil {
		ce.Reply("You are not logged in")
		return
	}

	api, ok := login.Client.(bridgev2.ContactListingNetworkAPI)
	if !ok {
		ce.Reply("This bridge does not support contact listing")
		return
	}

	ce.Reply("Syncing contacts from LINE...")
	contacts, err := api.GetContactList(ce.Ctx)
	if err != nil {
		ce.Reply("Failed to sync contacts: %v", err)
		return
	}

	for _, contact := range contacts {
		if contact.UserInfo != nil && contact.Ghost != nil {
			contact.Ghost.UpdateInfo(ce.Ctx, contact.UserInfo)
		}
	}

	ce.Reply("Synced %d contacts", len(contacts))
}

func main() {
	m := mxmain.BridgeMain{
		Name:        "matrix-line",
		Description: "A Matrix-LINE bridge",
		URL:         "https://github.com/highesttt/matrix-line-messenger",
		Version:     "1.0.1",
		Connector:   &connector.LineConnector{},
	}
	m.InitVersion(Tag, Commit, BuildTime)
	m.PreInit()
	m.Init()
	m.Bridge.Commands.(*commands.Processor).AddHandler(cmdSyncContacts)
	m.Start()
	exitCode := m.WaitForInterrupt()
	m.Stop()
	if exitCode != 0 {
		fmt.Printf("Bridge exited with code %d\n", exitCode)
	}
}
