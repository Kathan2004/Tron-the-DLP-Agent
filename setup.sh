#!/bin/bash
# Tron DLP: local development setup (virtualenv, dependencies, .env).
set -euo pipefail
cd "$(dirname "$0")"

command -v python3 >/dev/null || { echo "python3 not found"; exit 1; }
echo "Python: $(python3 --version)"

python3 -m venv venv
# shellcheck disable=SC1091
source venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

if [ ! -f .env ]; then
    cp .env.example .env
    chmod 600 .env
    # Generate the secrets that should never keep a placeholder value.
    python3 - <<'PY'
import base64, os, re, secrets
text = open(".env").read()
values = {
    "APP_AUTH_SECRET": secrets.token_urlsafe(48),
    "TRON_AGENT_TOKEN": secrets.token_urlsafe(32),
    "TRON_DATA_KEY": base64.urlsafe_b64encode(os.urandom(32)).decode(),
}
for key, value in values.items():
    text = re.sub(rf"(?m)^{key}=.*$", f"{key}={value}", text)
open(".env", "w").write(text)
PY
    echo "Created .env with generated APP_AUTH_SECRET, TRON_AGENT_TOKEN and TRON_DATA_KEY."
    echo "Back up TRON_DATA_KEY: stored findings cannot be decrypted without it."
fi

command -v tesseract >/dev/null || echo "Note: tesseract not found; images and scanned PDFs will be reported as not inspected."

cat <<'MSG'

Setup complete.
  ./start          API (127.0.0.1:5001) + console (localhost:5173)
  ./start_all.sh   API + endpoint, network and web agents
  docker compose up -d --build     API + console in containers (http://127.0.0.1:8080)

On first start the API prints a one-time admin password unless APP_ADMIN_PASSWORD is set.
MSG
