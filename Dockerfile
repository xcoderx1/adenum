# adenum - Active Directory enumeration toolkit
# Reproducible image with pinned Python tooling.
FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="adenum" \
      org.opencontainers.image.description="Active Directory enumeration & exploitation toolkit" \
      org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive

# Core + optional system tools the modules shell out to.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ldap-utils \
        jq \
        smbclient \
        dnsutils \
        ca-certificates \
        git \
    && rm -rf /var/lib/apt/lists/*

# Optional Python tooling (pinned for reproducible builds). These unlock the
# Kerberos/ADCS/BloodHound/exploitation features; the toolkit still runs without
# them (it degrades gracefully).
RUN pip install --no-cache-dir \
        impacket==0.12.0 \
        bloodhound==1.7.2 \
        certipy-ad==4.8.2 \
        bloodyAD==2.1.4 \
        netexec==1.3.0 \
    || echo "[!] some optional pip tools failed to install; core LDAP features still work"

WORKDIR /opt/adenum
COPY . /opt/adenum
RUN chmod +x ultimate_ad_enum.sh modules/*.sh tests/*.sh 2>/dev/null || true

# Drop to a non-root user for running assessments.
RUN useradd -m -s /bin/bash operator && chown -R operator:operator /opt/adenum
USER operator

ENTRYPOINT ["./ultimate_ad_enum.sh"]
CMD ["--help"]
