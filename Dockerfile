# infragpt — read-only infra assistant.
#
# Ships kubectl, psql, redis-cli, gcloud and aws.
#
# gcloud and aws were DELIBERATELY EXCLUDED originally, on the reasoning that
# those surfaces call REST directly, that a CLI is ~1GB, and that the safety
# story was "the model cannot run arbitrary commands". Two of those three
# stopped being true:
#
#   * The model CAN compose commands now (the shell:read surface), so the
#     absence was not a safety boundary — it was a dead end. Observed live: it
#     reached for `gcloud` to read Query Insights, got "not available", and
#     burned calls retrying.
#   * Some things have no REST equivalent in the registry. `gcloud logging read`
#     is the only route to GCP Cloud Logging from here.
#
# What actually bounds this is IAM, not the presence of a binary. The pod's
# service account holds exactly five roles — alloydb.viewer,
# container.clusterViewer, logging.viewer, monitoring.viewer, redis.viewer —
# with no Secret Manager and no IAM access, all read-only. Installing a CLI
# cannot widen that; it only makes reachable what the identity was already
# permitted to read.
#
# The cost is image size, which is why both are stripped below.
FROM python:3.13-slim AS base

ARG KUBECTL_VERSION=v1.31.4
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    INFRAGPT_DATA=/data \
    INFRAGPT_REGISTRY=/app/registry \
    INFRAGPT_RUNBOOKS=/data/runbooks

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates curl git gnupg unzip postgresql-client redis-tools sqlite3 tini; \
    arch="$(dpkg --print-architecture)"; \
    curl -fsSLo /usr/local/bin/kubectl \
        "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${arch}/kubectl"; \
    chmod 0755 /usr/local/bin/kubectl; \
    \
    # --- gcloud ----------------------------------------------------------- \
    # Installed from Google's apt repo, then stripped: the bundled Python is
    # redundant (the image already has 3.13), and the docs/examples are dead
    # weight in a container. Roughly halves what the package brings in.
    curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg \
        | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg; \
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] \
https://packages.cloud.google.com/apt cloud-sdk main" \
        > /etc/apt/sources.list.d/google-cloud-sdk.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends google-cloud-cli; \
    # gsutil and bq are KEPT — they are read-capable tools in their own right
    # (`gsutil ls`, `bq show`), and the shell guard governs which verbs may run,
    # not which binaries exist. Only genuinely redundant weight is removed: the
    # bundled Python (this image already has 3.13), the installer backup, the
    # offline help, and vendored test suites. No tool is dropped.
    rm -rf \
        /usr/lib/google-cloud-sdk/platform/bundledpythonunix \
        /usr/lib/google-cloud-sdk/.install/.backup \
        /usr/lib/google-cloud-sdk/help \
        /usr/lib/google-cloud-sdk/lib/third_party/*/tests \
        /usr/lib/google-cloud-sdk/platform/gsutil/third_party/*/tests; \
    \
    # --- aws cli v2 -------------------------------------------------------- \
    case "$arch" in \
        amd64) awsarch=x86_64 ;; \
        arm64) awsarch=aarch64 ;; \
        *) awsarch=x86_64 ;; \
    esac; \
    curl -fsSLo /tmp/awscli.zip \
        "https://awscli.amazonaws.com/awscli-exe-linux-${awsarch}.zip"; \
    unzip -q /tmp/awscli.zip -d /tmp; \
    /tmp/aws/install --bin-dir /usr/local/bin --install-dir /usr/local/aws-cli; \
    rm -rf /tmp/awscli.zip /tmp/aws \
        /usr/local/aws-cli/v2/*/dist/awscli/examples; \
    \
    apt-get purge -y --auto-remove gnupg unzip; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir \
      "fastapi>=0.115" "uvicorn[standard]>=0.32" "pydantic>=2.9" "pyyaml>=6.0" \
      "httpx>=0.27" "psycopg[binary,pool]>=3.2" "redis>=5.2" \
      "python-jose[cryptography]>=3.3" "typer>=0.15" "rich>=13.9" "jinja2>=3.1"

COPY app ./app
COPY cli ./cli
COPY registry ./registry
COPY runbooks ./runbooks-seed
COPY scripts ./scripts

# The registry is baked into the image and mounted read-only at runtime: what the
# assistant can run is a property of the build, not of anything writable at
# runtime. Runbooks are seeded onto the PV so they can be edited without a
# rebuild — they change answer *quality*, never capability.
RUN chmod -R a-w /app/registry

# Non-root, no shell for the runtime user.
RUN useradd --system --uid 10001 --home /data --shell /usr/sbin/nologin infragpt \
 && mkdir -p /data && chown -R 10001:10001 /data
USER 10001

EXPOSE 8000
ENTRYPOINT ["/usr/bin/tini", "--"]
# Seed runbooks on every start, OVERWRITING what is on the volume.
#
# This was `cp -rn` (no-clobber), which meant a runbook that already existed on
# the volume could never be updated by a deploy: corrections shipped in the
# image were silently ignored for the lifetime of the PV, and the model kept
# reading the first version ever deployed. Nothing writes runbooks at runtime —
# they are versioned in git and there is no editing path — so the image is the
# source of truth and overwriting is correct.
#
# Files only on the volume are still left alone, so anything hand-placed there
# survives.
# Source clones are refreshed in the BACKGROUND. A first clone of a large
# repository takes minutes, and the API must answer infrastructure questions
# meanwhile — code functions report "not cloned yet" until the tree lands.
CMD ["sh", "-c", "cp -r /app/runbooks-seed/. /data/runbooks/ 2>/dev/null; \
     (sh /app/scripts/sync_code.sh 2>&1 | sed 's/^/[code] /' &) ; \
     exec uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8000"]
