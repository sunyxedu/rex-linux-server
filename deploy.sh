#!/bin/bash
set -e
echo "=== Rex Server Deployment for Devbox ==="
echo "Step 1: Installing dependencies..."

# Install Zig 0.16.0
if [ ! -f /tmp/zig-x86_64-linux-0.16.0/zig ]; then
    cd /tmp
    curl -sLO "https://ziglang.org/download/0.16.0/zig-x86_64-linux-0.16.0.tar.xz"
    tar xf zig-x86_64-linux-0.16.0.tar.xz
    echo "  Zig 0.16.0 installed"
else
    echo "  Zig 0.16.0 already installed"
fi

# Install Go (if not present)
if ! command -v go &>/dev/null; then
    cd /tmp
    curl -sLO "https://go.dev/dl/go1.23.3.linux-amd64.tar.gz"
    sudo tar -C /usr/local -xzf go1.23.3.linux-amd64.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo "  Go installed"
else
    echo "  Go already installed"
fi
export PATH=$PATH:/usr/local/go/bin

echo "Step 2: Cloning Ghostty and building libghostty-vt..."
if [ ! -f /tmp/ghostty/zig-out/lib/libghostty-vt.a ]; then
    cd /tmp
    [ -d ghostty ] || git clone --depth 1 https://github.com/ghostty-org/ghostty.git
    cd ghostty
    /tmp/zig-x86_64-linux-0.16.0/zig build -Demit-lib-vt=true -j4
    echo "  libghostty-vt built"
else
    echo "  libghostty-vt already built"
fi

echo "Step 3: Cloning rex-linux-server..."
cd /tmp
[ -d rex-linux-server ] && rm -rf rex-linux-server
git clone https://github.com/sunyxedu/rex-linux-server.git
cd rex-linux-server

echo "Step 4: Building rex-server with libghostty-vt..."
CGO_ENABLED=1 \
CGO_CFLAGS="-I/tmp/ghostty/zig-out/include" \
CGO_LDFLAGS="-L/tmp/ghostty/zig-out/lib -lghostty-vt -lm -lpthread" \
go build -o rex-server .
echo "  rex-server built"

echo "Step 5: Installing..."
sudo cp rex-server /usr/local/bin/rex-server
sudo chmod +x /usr/local/bin/rex-server

echo "Step 6: Installing Tailscale..."
if ! command -v tailscale &>/dev/null; then
    curl -fsSL https://tailscale.com/install.sh | sudo sh
    sudo systemctl enable --now tailscaled
    echo "  Tailscale installed. Run: sudo tailscale up --ssh --hostname=devbox-rex"
    echo "  Then visit the URL it gives you to authorize."
else
    echo "  Tailscale already installed"
    tailscale status --self 2>/dev/null | head -1
fi

echo "Step 7: Setting up systemd service..."
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/rex-server.service << 'SVC'
[Unit]
Description=Rex-compatible terminal server
After=network.target

[Service]
ExecStart=/usr/local/bin/rex-server -listen :7297 -account %u
Restart=always
RestartSec=3
Environment=LD_LIBRARY_PATH=/tmp/ghostty/zig-out/lib

[Install]
WantedBy=default.target
SVC

loginctl enable-linger $(whoami) 2>/dev/null || true
systemctl --user daemon-reload
systemctl --user enable --now rex-server
echo "  rex-server service started"

echo "Step 8: Setting up Tailscale Serve..."
sudo tailscale serve --bg --https=443 http://localhost:7297 2>/dev/null || echo "  (run after tailscale up)"

echo ""
echo "=== DONE ==="
echo "Rex server is running on port 7297"
echo ""
echo "Next steps:"
echo "1. If Tailscale isn't connected yet: sudo tailscale up --ssh --hostname=devbox-rex"
echo "2. Visit the auth URL to authorize"
echo "3. Then run: sudo tailscale serve --bg --https=443 http://localhost:7297"
echo "4. Add in Rex.app: https://devbox-rex.tailbfe271.ts.net"
