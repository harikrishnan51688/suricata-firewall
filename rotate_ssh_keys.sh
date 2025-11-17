#!/bin/bash

set -e

REMOTE_USER="admin"
REMOTE_HOST="10.21.232.1"
OLD_KEY_PATH="$HOME/.ssh/id_ed25519"
NEW_KEY_PATH="$HOME/.ssh/id_ed25519_new"
LOG_FILE="$HOME/.ssh/key_rotation.log"

if [ -f "$NEW_KEY_PATH" ]; then
    echo "[INFO] Old new-key file exists. Removing..."
    rm -f "$NEW_KEY_PATH" "$NEW_KEY_PATH.pub"
fi

ssh-keygen -t ed25519 -f "$NEW_KEY_PATH" -C "rotated-$(date +%Y%m%d)" >> "$LOG_FILE"

ssh-copy-id -i "$NEW_KEY_PATH.pub" "$REMOTE_USER@$REMOTE_HOST" >> "$LOG_FILE"

echo "[INFO] Verifying new key access..."
if ssh -i "$NEW_KEY_PATH" -o BatchMode=yes -o ConnectTimeout=10 "$REMOTE_USER@$REMOTE_HOST" "echo 'New key verified'"; then
    echo "[SUCCESS] Verified new key works!"
else
    echo "[ERROR] New key failed to authenticate. Keeping old key."
    exit 1
fi


OLD_PUB_KEY=$(ssh-keygen -y -f "$OLD_KEY_PATH")
ssh -i "$NEW_KEY_PATH" "$REMOTE_USER@$REMOTE_HOST" "grep -v '$OLD_PUB_KEY' ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.tmp && mv ~/.ssh/authorized_keys.tmp ~/.ssh/authorized_keys"
echo "[INFO] Old key removed from remote authorized_keys"