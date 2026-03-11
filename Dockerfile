FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# System packages: node-pty build deps, network utilities, vim, git
RUN apt-get update && apt-get install -y \
    tini \
    curl \
    wget \
    vim \
    git \
    build-essential \
    python3 \
    dnsutils \
    iputils-ping \
    telnet \
    netcat-openbsd \
    traceroute \
    net-tools \
    iproute2 \
    openssh-client \
    ca-certificates \
    gnupg \
    sudo \
    jq \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js 22.x LTS
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Create dev user (uid/gid 1001)
RUN groupadd -g 1001 dev \
    && useradd -m -u 1001 -g 1001 -s /bin/bash dev \
    && echo 'dev ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers \
    && cp /etc/skel/.profile /home/dev/.profile \
    && chown dev:dev /home/dev/.profile

# Create devops user (uid/gid 1002)
RUN groupadd -g 1002 devops \
    && useradd -m -u 1002 -g 1002 -s /bin/bash devops \
    && echo 'devops ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers \
    && cp /etc/skel/.profile /home/devops/.profile \
    && chown devops:devops /home/devops/.profile

# Install kubectl and k9s into /opt/devops/bin (devops-only, not on dev's PATH)
RUN mkdir -p /opt/devops/bin \
    && curl -fsSL "https://dl.k8s.io/release/$(curl -sL https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" -o /opt/devops/bin/kubectl \
    && chmod +x /opt/devops/bin/kubectl \
    && curl -fsSL -L https://github.com/derailed/k9s/releases/download/v0.50.18/k9s_Linux_amd64.tar.gz | tar xz -C /opt/devops/bin k9s \
    && chmod +x /opt/devops/bin/k9s

# Add devops-only PATH
RUN echo 'export PATH="/opt/devops/bin:$HOME/.local/bin:$PATH"' >> /home/devops/.bashrc

# Install global npm packages as root
RUN npm i -g @openai/codex @google/gemini-cli

# Set up the terminal server app
WORKDIR /app
COPY package.json tsconfig.json ./
COPY src/ ./src/
RUN npm install && npm run build && rm -rf src && npm prune --omit=dev

RUN mkdir -p /etc/runostty

# Add CLI tool paths to system-wide PATH (survives PVC mount)
RUN echo 'export PATH="$HOME/.local/bin:$HOME/.opencode/bin:$PATH"' > /etc/profile.d/runostty-path.sh \
    && chmod +x /etc/profile.d/runostty-path.sh \
    && echo 'export PATH="$HOME/.local/bin:$HOME/.opencode/bin:$PATH"' >> /etc/bash.bashrc

# Install CLI tools as dev user, then stage them outside /home/dev
USER dev
WORKDIR /home/dev

# Bump the number to force a fresh install of that CLI
ARG CLAUDE_VER=2
RUN curl -fsSL https://claude.ai/install.sh | bash

ARG RUNOS_VER=5
ARG RUNOS_ENV=dev
ENV RUNOS_ENV=${RUNOS_ENV}
RUN curl -fsSL https://get.${RUNOS_ENV}.runos.com/cli.sh | bash

ARG OPENCODE_VER=2
RUN curl -fsSL https://opencode.ai/install | bash

USER root

# Stage home directories so entrypoint can restore them on fresh PVC
RUN cp -a /home/dev /opt/runostty-skel
RUN cp -a /home/devops /opt/runostty-skel-devops

# Copy entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /app

EXPOSE 7681

ENTRYPOINT ["tini", "--", "/entrypoint.sh"]
