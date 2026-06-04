#!/data/data/com.termux/files/usr/bin/bash
# =============================================================
#  WebVulnConsole ⚡ – Termux Setup & Launch Script
#  Authorized Security Testing Platform
#  Run once on a fresh Termux install to set everything up.
# =============================================================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
BOLD='\033[1m'
RESET='\033[0m'

BANNER="
${CYAN}${BOLD}  ┌────────────────────────────────────────────┐
  │   ⚡  WebVulnConsole  v1.0.0               │
  │   Authorized Security Testing Platform    │
  └────────────────────────────────────────────┘${RESET}
"

echo -e "$BANNER"

menu() {
  echo -e "${BOLD}${CYAN}  Select an option:${RESET}"
  echo -e "  ${GREEN}1)${RESET} Install everything (first-time setup)"
  echo -e "  ${GREEN}2)${RESET} Launch WebVulnConsole server"
  echo -e "  ${GREEN}3)${RESET} Update repo (git pull)"
  echo -e "  ${GREEN}4)${RESET} Show server status"
  echo -e "  ${GREEN}5)${RESET} Exit"
  echo ""
  read -p "  > " CHOICE
  case $CHOICE in
    1) install ;;
    2) launch  ;;
    3) update  ;;
    4) status  ;;
    5) exit 0  ;;
    *) echo -e "${RED}Invalid option.${RESET}"; menu ;;
  esac
}

install() {
  echo -e "\n${YELLOW}[⚡] Starting full install...${RESET}\n"

  # Update Termux packages.
  echo -e "${CYAN}[1/6] Updating Termux packages...${RESET}"
  pkg update -y && pkg upgrade -y

  # Install core deps.
  echo -e "${CYAN}[2/6] Installing dependencies: nodejs git...${RESET}"
  pkg install -y nodejs git

  # Install curl (needed for health checks).
  pkg install -y curl

  # Grant storage permission (optional, for saving reports).
  echo -e "${CYAN}[3/6] Requesting storage permission...${RESET}"
  termux-setup-storage 2>/dev/null || true

  # Clone or pull repo.
  REPO_URL="https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console.git"
  REPO_DIR="$HOME/web-vuln-console"

  if [ -d "$REPO_DIR/.git" ]; then
    echo -e "${CYAN}[4/6] Repo exists. Pulling latest...${RESET}"
    cd "$REPO_DIR" && git pull
  else
    echo -e "${CYAN}[4/6] Cloning repo...${RESET}"
    git clone "$REPO_URL" "$REPO_DIR"
  fi

  # Install Node deps.
  echo -e "${CYAN}[5/6] Installing Node.js dependencies...${RESET}"
  cd "$REPO_DIR/backend" && npm install

  # Create data directory.
  mkdir -p "$REPO_DIR/backend/data"

  # Write a launcher shortcut.
  echo -e "${CYAN}[6/6] Creating launch shortcut...${RESET}"
  cat > "$HOME/wvc.sh" << 'LAUNCHER'
#!/data/data/com.termux/files/usr/bin/bash
cd $HOME/web-vuln-console/backend && node server.js
LAUNCHER
  chmod +x "$HOME/wvc.sh"

  echo -e "\n${GREEN}[✓] Install complete!${RESET}"
  echo -e "${GREEN}    Run: bash ~/wvc.sh   to launch server${RESET}"
  echo -e "${GREEN}    Or pick option 2 from this menu.${RESET}\n"

  read -p "Launch server now? [y/N] " LAUNCH_NOW
  if [[ "$LAUNCH_NOW" =~ ^[Yy]$ ]]; then
    launch
  else
    menu
  fi
}

launch() {
  REPO_DIR="$HOME/web-vuln-console"
  if [ ! -d "$REPO_DIR/backend/node_modules" ]; then
    echo -e "${RED}[!] Dependencies not installed. Run option 1 first.${RESET}"
    menu
    return
  fi

  # Get LAN IP for easy phone-to-laptop access.
  LAN_IP=$(ip route get 1 2>/dev/null | awk '{print $NF; exit}' || hostname -I 2>/dev/null | awk '{print $1}')
  PORT=$(grep -o '"port":[0-9]*' "$REPO_DIR/backend/config.js" 2>/dev/null | grep -o '[0-9]*' | head -1)
  PORT=${PORT:-8787}

  echo -e "\n${GREEN}[⚡] Launching WebVulnConsole...${RESET}"
  echo -e "${CYAN}    Local:    http://127.0.0.1:${PORT}${RESET}"
  echo -e "${CYAN}    LAN:      http://${LAN_IP}:${PORT}${RESET}"
  echo -e "${YELLOW}    Open the URL above in your browser.${RESET}"
  echo -e "${YELLOW}    Press Ctrl+C to stop.${RESET}\n"

  cd "$REPO_DIR/backend" && node server.js
}

update() {
  REPO_DIR="$HOME/web-vuln-console"
  echo -e "\n${CYAN}[↻] Pulling latest from GitHub...${RESET}"
  cd "$REPO_DIR" && git pull
  echo -e "${CYAN}[↻] Updating Node dependencies...${RESET}"
  cd backend && npm install
  echo -e "${GREEN}[✓] Updated!${RESET}\n"
  menu
}

status() {
  echo -e "\n${CYAN}[?] Checking server status...${RESET}"
  PORT=$(grep -o '"port":[0-9]*' "$HOME/web-vuln-console/backend/config.js" 2>/dev/null | grep -o '[0-9]*' | head -1)
  PORT=${PORT:-8787}
  if curl -sf "http://127.0.0.1:${PORT}/api/health" > /dev/null 2>&1; then
    echo -e "${GREEN}[✓] Server is RUNNING on port ${PORT}${RESET}"
    curl -s "http://127.0.0.1:${PORT}/api/health" | python3 -m json.tool 2>/dev/null || true
  else
    echo -e "${RED}[x] Server is NOT running.${RESET}"
  fi
  echo ""
  menu
}

menu
