# Docker Base-Image Digest-Pinning

## Warum Digest-Pinning?

Tags wie `rust:1-bookworm` oder `debian:bookworm-slim` können sich ändern (neue Builds, Security-Patches). Für maximale Reproduzierbarkeit pinnen wir Images per **SHA256-Digest**.

## Digests ermitteln

### Methode 1: Docker CLI (lokal)
```bash
# Pull + Inspect
docker pull rust:1-bookworm
docker inspect rust:1-bookworm --format='{{index .RepoDigests 0}}'
# Output: rust@sha256:abc123...

docker pull debian:bookworm-slim
docker inspect debian:bookworm-slim --format='{{index .RepoDigests 0}}'
# Output: debian@sha256:def456...
```

### Methode 2: Docker Hub API (ohne Docker)
```bash
# Rust 1-bookworm (Multi-Arch Manifest)
curl -s -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
  https://registry-1.docker.io/v2/library/rust/manifests/1-bookworm \
  | jq -r '.config.digest'

# Debian bookworm-slim
curl -s -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
  https://registry-1.docker.io/v2/library/debian/manifests/bookworm-slim \
  | jq -r '.config.digest'
```

### Methode 3: Crane (Google Container Tools)
```bash
# Installation
go install github.com/google/go-containerregistry/cmd/crane@latest

# Digest holen
crane digest rust:1-bookworm
crane digest debian:bookworm-slim
```

## Dockerfile mit Digest-Pinning

**Aktuell (Dockerfile):**
```dockerfile
ARG BASE_RUNTIME=debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421
ARG BASE_BUILDER=rust:1-bookworm@sha256:ca8d52cf3eadfe814328f1cff05e3f0022b4cf696ddc8498ef26b52f71b201ad
FROM ${BASE_BUILDER} AS builder
FROM ${BASE_RUNTIME} AS runtime
```

**Update-Muster (Beispiel mit denselben Build-Args):**
```dockerfile
ARG BASE_RUNTIME=debian:bookworm-slim@sha256:<new-debian-digest>
ARG BASE_BUILDER=rust:1-bookworm@sha256:<new-rust-digest>
FROM ${BASE_BUILDER} AS builder
FROM ${BASE_RUNTIME} AS runtime
```

## Update-Prozedur (monatlich)

```bash
# 1. Neue Digests holen
NEW_RUST=$(crane digest rust:1-bookworm)
NEW_DEBIAN=$(crane digest debian:bookworm-slim)

# 2. Dockerfile updaten
sed -i "s|rust@sha256:[a-f0-9]*|rust@$NEW_RUST|" Dockerfile
sed -i "s|debian@sha256:[a-f0-9]*|debian@$NEW_DEBIAN|" Dockerfile

# 3. Lokal testen
docker build -t phantom-node:test .

# 4. Committen
git add Dockerfile
git commit -m "chore(docker): update base-image digests (monthly)"
git push
```

## Verifizierung

```bash
# Dockerfile-FROM-Zeilen anzeigen
grep -E "^(ARG BASE_|FROM)" Dockerfile

# Erwartete Ausgabe:
# ARG BASE_RUNTIME=debian:bookworm-slim@sha256:...
# ARG BASE_BUILDER=rust:1-bookworm@sha256:...
# FROM ${BASE_BUILDER} AS builder
# FROM ${BASE_RUNTIME} AS runtime
```

## Trade-offs

**Vorteile:**
- ✅ Byte-genaue Reproduzierbarkeit
- ✅ Schutz vor Tag-Mutation
- ✅ Supply-Chain-Attack-Prävention

**Nachteile:**
- ⚠️ Keine automatischen Security-Updates (Base-Images)
- ⚠️ Manueller Update-Prozess erforderlich
- ⚠️ Digests müssen monatlich aktualisiert werden

**Empfehlung:** 
- **Release-Builds**: Digest-Pinning im produktiven `Dockerfile`
- **Development**: dieselben Build-Args beibehalten und Digests bewusst aktualisieren
- **Hybrid**: Digests per Build-Arg austauschbar halten, aber niemals ungepinnt releasen

## CI-Integration

**Option 1: Digest-Override in GitHub Actions**
```yaml
# .github/workflows/release.yml
- name: Build Docker image (digest-pinned)
  run: |
    # Base-Images mit Digest-Override
    docker build \
      --build-arg BASE_BUILDER=rust@sha256:abc123... \
      --build-arg BASE_RUNTIME=debian@sha256:def456... \
      -t phantom-node:${{ github.ref_name }} .
```

**Option 2: Separate Dockerfiles**
```
Dockerfile                    # Dev (Tag-basiert)
Dockerfile.release            # Prod (Digest-pinned)
```

## Referenzen
- [Docker Content Trust](https://docs.docker.com/engine/security/trust/)
- [Reproducible Builds: Docker](https://reproducible-builds.org/docs/docker/)
- [Crane Tool](https://github.com/google/go-containerregistry/blob/main/cmd/crane/README.md)
