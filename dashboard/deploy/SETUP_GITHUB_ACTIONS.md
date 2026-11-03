# Setting up GitHub Actions Deployment

To make the automated deployment pipeline work, you need to configure three secrets in the GitHub Repository settings (`Settings` -> `Secrets and variables` -> `Actions`).

### 1. Tailscale OAuth Client
The runner needs to join your Tailscale network to reach `example-prod-host`.
1. Go to the [Tailscale Admin Console - OAuth Clients](https://login.tailscale.com/admin/settings/oauth).
2. Generate a new OAuth Client. Give it the `Devices: Write` scope and attach the tag `tag:ci` (you may need to create this tag in your ACLs first).
3. Add the Client ID as a GitHub Secret: `TS_OAUTH_CLIENT_ID`
4. Add the Client Secret as a GitHub Secret: `TS_OAUTH_SECRET`

*Note: Your Tailscale ACLs must allow `tag:ci` to access port 22 on `example-prod-host`.*

### 2. Deployment SSH Key
The runner needs an SSH key to authenticate against `example-prod-host`.
1. SSH into the VPS manually from your Mac: `ssh root@example-prod-host`
2. Generate a dedicated Ed25519 keypair for GitHub Actions:
   ```bash
   ssh-keygen -t ed25519 -C "github-actions-deploy" -f /root/.ssh/id_ed25519_github_actions -N ""
   ```
3. Add the public key to the authorized_keys file:
   ```bash
   cat /root/.ssh/id_ed25519_github_actions.pub >> /root/.ssh/authorized_keys
   ```
4. Cat the private key to copy it:
   ```bash
   cat /root/.ssh/id_ed25519_github_actions
   ```
5. Add the private key string as a GitHub Secret: `DEPLOY_SSH_KEY`

### 3. Initialize Git on the VPS
Currently, `/opt/patched-dashboard` is just a folder of files copied via `scp`. We need to turn it into a real git repository so the script can run `git pull`.
1. SSH into the VPS: `ssh root@example-prod-host`
2. Run the following:
   ```bash
   cd /opt/patched-dashboard
   git init
   git remote add origin `Patched-LTD/dashboard.git`
   git fetch origin
   git reset --hard origin/main
   chown -R root:root /opt/patched-dashboard   # PAT-2307: root's, never www-data's
   ```

Once these three steps are complete, any push to the `main` branch will automatically deploy to production.
