#!/bin/bash

if [[ -z "$GID" ]]; then
	GID="$UID"
fi

BINARY_NAME=/usr/bin/matrix-line

function fixperms {
	chown -R $UID:$GID /data
}

if [[ ! -f /data/config.yaml ]]; then
	$BINARY_NAME -c /data/config -e
	echo "Didn't find a config file."
	echo "Copied default config file to /data/config.yaml"
	echo "Modify that config file to your liking."
	echo "Start the container again after that to generate the registration file."
	exit
fi

if [[ ! -f /data/registration.yaml ]]; then
	if grep -q 'as_token.*This value is generated' /data/config.yaml 2>/dev/null; then
		# Config has placeholder tokens (self-hosted setup). Generate normally.
		$BINARY_NAME -g -c /data/config.yaml -r /data/registration.yaml || exit $?
		echo "Didn't find a registration file."
		echo "Generated one for you."
		echo "See https://docs.mau.fi/bridges/general/registering-appservices.html on how to use it."
		exit
	fi
	# Config already has real tokens (e.g. from Beeper/bbctl). Build the
	# registration from existing config values instead of generating new
	# random tokens that would overwrite the valid ones.
	echo "Config already has tokens set. Generating registration.yaml from config..."
	AS_TOKEN=$(yq '.appservice.as_token' /data/config.yaml)
	HS_TOKEN=$(yq '.appservice.hs_token' /data/config.yaml)
	APP_ID=$(yq '.appservice.id' /data/config.yaml)
	APP_URL=$(yq '.appservice.address' /data/config.yaml)
	BOT_USER=$(yq '.appservice.bot.username' /data/config.yaml)
	EPHEMERAL=$(yq '.appservice.ephemeral_events' /data/config.yaml)
	HS_DOMAIN=$(yq '.homeserver.domain' /data/config.yaml)
	USERNAME_TPL=$(yq '.appservice.username_template' /data/config.yaml)
	# Build the user namespace regex from the username template and domain.
	# The template uses {{.}} as placeholder, replace with .+ for the regex.
	USER_REGEX=$(echo "$USERNAME_TPL" | sed 's/{{\.}}/.+/g')
	USER_REGEX="@${USER_REGEX}:${HS_DOMAIN}"
	# Escape dots in the regex for YAML
	USER_REGEX=$(echo "$USER_REGEX" | sed 's/\./\\./g')
	yq -n "
		.id = \"${APP_ID}\" |
		.url = \"${APP_URL}\" |
		.as_token = \"${AS_TOKEN}\" |
		.hs_token = \"${HS_TOKEN}\" |
		.sender_localpart = \"${BOT_USER}\" |
		.namespaces.users[0].regex = \"${USER_REGEX}\" |
		.namespaces.users[0].exclusive = true |
		.receive_ephemeral = ${EPHEMERAL:-true}
	" > /data/registration.yaml
	chmod 600 /data/registration.yaml
	echo "Generated registration.yaml from existing config tokens."
fi

cd /data
fixperms
exec su-exec $UID:$GID $BINARY_NAME
