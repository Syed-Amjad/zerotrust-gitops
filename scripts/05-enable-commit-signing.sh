#!/usr/bin/env bash
# OPTIONAL — the second half of layer 2: require GPG-signed commits.
#
#   ./scripts/05-enable-commit-signing.sh
#
# Run on your WORKSTATION, not on the box, because it configures the git
# identity you commit with. It then needs kubectl access to import the public
# key into ArgoCD, so run it with the cluster reachable (through the tunnel).
#
# =========================================================================
# WHY THIS IS A SEPARATE, OPTIONAL STEP.
#
# Once the AppProject carries signatureKeys, EVERY commit at the target
# revision of EVERY Application in the project must be signed by one of those
# keys. An unsigned commit does not warn — the sync fails with:
#
#   target revision <sha> is not signed
#
# That includes commits made by CI. The bump-gitops job writes image digests
# into this repository as `ci-bot`, which has no GPG key, so enabling this
# WILL break the automated digest bump until CI is given a signing key too.
#
# That is not a flaw in the control; it is the control working. Signed commits
# mean "a human with this key approved this change", and a pipeline that can
# sign on its own behalf has given that property away. The honest resolutions
# are: give CI its own key and list it separately so it is auditable as a
# machine identity, or have CI open a pull request instead of pushing.
#
# This script sets it up for YOUR key only, prints exactly what will break,
# and asks before patching. Getting locked out of your own GitOps repo at
# 11pm is a bad way to learn how this works.
# =========================================================================
set -euo pipefail

hdr()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m    %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m    %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m!!! %s\033[0m\n' "$*" >&2; exit 1; }
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"

EMAIL="${GIT_SIGN_EMAIL:-syed.amjad.hashmi@gmail.com}"
NAME="${GIT_SIGN_NAME:-Syed Amjad}"

command -v gpg >/dev/null || die "gpg is not installed: sudo apt-get install -y gnupg"

hdr "Looking for an existing signing key for ${EMAIL}"
KEYID="$(gpg --list-secret-keys --keyid-format=long "$EMAIL" 2>/dev/null \
          | awk '/^sec/ {split($2,a,"/"); print a[2]; exit}' || true)"

if [[ -z "$KEYID" ]]; then
  warn "No secret key found. Generating one (ed25519, no passphrase)."
  warn "No passphrase is a LAB choice: a passphrase-protected key cannot sign"
  warn "unattended, and prompting mid-script is worse than saying so here. A"
  warn "real signing key has a passphrase and lives on a hardware token."
  gpg --batch --quick-generate-key "${NAME} <${EMAIL}>" ed25519 sign never
  KEYID="$(gpg --list-secret-keys --keyid-format=long "$EMAIL" \
            | awk '/^sec/ {split($2,a,"/"); print a[2]; exit}')"
fi
ok "key id: ${KEYID}"

hdr "Configuring git to sign every commit"
git config --global user.signingkey "$KEYID"
git config --global commit.gpgsign true
git config --global tag.gpgsign true
ok "commit.gpgsign = true (global)"

hdr "Importing the PUBLIC half into ArgoCD"
# ---------------------------------------------------------------------------
# ArgoCD keeps trusted keys in a ConfigMap, keyed by key id. Only the public
# half goes in — ArgoCD verifies, it never signs.
#
# `argocd gpg add` does the same thing through the API and needs a logged-in
# CLI; patching the ConfigMap works from kubectl alone, which is one fewer
# moving part at the point where you are already changing how commits work.
# ---------------------------------------------------------------------------
PUB="$(gpg --armor --export "$KEYID")"
[[ -n "$PUB" ]] || die "Could not export the public key"
kubectl -n argocd create configmap argocd-gpg-keys-cm \
  --from-literal="${KEYID}=${PUB}" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n argocd rollout restart deploy/argocd-repo-server
kubectl -n argocd rollout status deploy/argocd-repo-server --timeout=180s
ok "key ${KEYID} is trusted by ArgoCD"

hdr "What patching the AppProject will do"
cat <<MSG
    Every Application in the `zerotrust` project will refuse to sync unless the
    commit at its target revision carries a valid signature from ${KEYID}.

    THIS WILL BREAK, until you address it:
      * the CI bump-gitops job, which pushes as ci-bot with no key
      * any commit you make from another machine without this key
      * any commit made through the GitHub web UI
        (GitHub signs those with ITS OWN key, not yours)

    Known ArgoCD limitation: signature verification works for git sources only,
    not Helm chart sources. It happens not to matter here — every Application
    in this repo has a git source — and that is partly why Kyverno and Falco
    are installed by script instead.

    To undo:
      kubectl -n argocd patch appproject zerotrust --type json \
        -p '[{"op":"remove","path":"/spec/signatureKeys"}]'
MSG

read -r -p "    Patch the AppProject to require signed commits? [y/N] " reply
if [[ ! "$reply" =~ ^[Yy]$ ]]; then
  warn "Not patched. Your git is now signing commits, which is harmless and"
  warn "worth keeping. Re-run this script when you want to enforce it."
  exit 0
fi

kubectl -n argocd patch appproject zerotrust --type merge \
  -p "{\"spec\":{\"signatureKeys\":[{\"keyID\":\"${KEYID}\"}]}}"
ok "AppProject now requires signatures from ${KEYID}"

hdr "Verify"
cat <<'MSG'
    Make a signed commit and confirm it syncs:
      git commit --allow-empty -m "test: signed commit" && git push
      kubectl -n argocd get app -o wide

    Then confirm an UNSIGNED commit is refused — this is the actual test:
      git -c commit.gpgsign=false commit --allow-empty -m "test: unsigned"
      git push
      kubectl -n argocd get app root -o jsonpath='{.status.conditions}' | jq

    Expect: "target revision <sha> is not signed". Record both results; the
    second one is the only one that proves the control is on.
MSG
