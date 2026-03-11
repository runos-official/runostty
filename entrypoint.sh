#!/bin/bash
set -e

# On fresh PVC, /home/dev will be empty. Restore from skeleton.
if [ ! -f /home/dev/.bashrc ]; then
    echo "Fresh PVC detected — setting up /home/dev from skeleton..."
    cp -a /opt/runostty-skel/. /home/dev/
    chown -R dev:dev /home/dev
fi

# Always sync CLI tools from skeleton (handles image upgrades)
cp -an /opt/runostty-skel/.local/. /home/dev/.local/ 2>/dev/null || true
cp -an /opt/runostty-skel/.opencode/. /home/dev/.opencode/ 2>/dev/null || true
chown -R dev:dev /home/dev/.local /home/dev/.opencode 2>/dev/null || true

# devops user — same skeleton pattern as dev
if [ ! -f /home/devops/.bashrc ]; then
    echo "Fresh devops PVC detected — setting up /home/devops from skeleton..."
    cp -a /opt/runostty-skel-devops/. /home/devops/
    chown -R devops:devops /home/devops
fi

# Always sync runos CLI from dev skeleton (handles image upgrades)
mkdir -p /home/devops/.local/bin
cp -an /opt/runostty-skel/.local/bin/runos /home/devops/.local/bin/runos 2>/dev/null || true
chown -R devops:devops /home/devops/.local

# First-time runos CLI setup (token is single-use, so only run once)
if [ ! -d /home/dev/.runos ]; then
    if [ "$RUNOS_ENV" = "dev" ]; then
        su - dev -c "runos config env dev" 2>/dev/null || true
    fi
    if [ -n "$RUNOS_DEVICE_ID" ] && [ -n "$RUNOS_CLI_TOKEN" ]; then
        su - dev -c "runos login preauth --device-id $RUNOS_DEVICE_ID --token $RUNOS_CLI_TOKEN" 2>/dev/null || true
    fi
    if [ -d /home/dev/.runos ]; then
        cp -a /home/dev/.runos /home/devops/.runos
        chown -R devops:devops /home/devops/.runos
    fi
fi

# Generate kubeconfig from in-cluster service account (k9s needs an explicit context)
SA_DIR="/var/run/secrets/kubernetes.io/serviceaccount"
if [ -f "$SA_DIR/token" ]; then
    mkdir -p /home/devops/.kube
    cat > /home/devops/.kube/config <<KUBEEOF
apiVersion: v1
kind: Config
clusters:
  - name: cluster
    cluster:
      server: https://kubernetes.default.svc
      certificate-authority: ${SA_DIR}/ca.crt
users:
  - name: sa
    user:
      tokenFile: ${SA_DIR}/token
contexts:
  - name: default
    context:
      cluster: cluster
      user: sa
current-context: default
KUBEEOF
    chown -R devops:devops /home/devops/.kube
fi

exec node /app/dist/server.js
