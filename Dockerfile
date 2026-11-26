# PK95 File als Container für PK95 Core (ghcr.io/philippkuhlmann/pk95-file).
# Samba-Mitgliedsserver (Debian trixie, Samba 4.22) mit Freigaben in der PK95-AD-Domäne plus die Admin-API (Python,
# Port 8445). Läuft mit network_mode host und einer eigenen LAN-Adresse auf eth0 (NET_ADMIN, NET_RAW); smbd bindet
# nur an diese Adresse, der DC behält 445 auf der Hauptadresse des LXC. Siehe docs/design.md.

FROM debian:trixie-slim

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
		samba samba-vfs-modules winbind libnss-winbind smbclient krb5-user python3-samba \
		iproute2 iputils-arping acl attr rsync procps tini tzdata ca-certificates \
	&& rm -rf /var/lib/apt/lists/* \
	# The image ships no join: setup writes smb.conf and secrets into the volumes.
	&& rm -f /etc/samba/smb.conf /etc/krb5.conf \
	&& rm -rf /var/lib/samba/* /var/cache/samba/* \
	&& mkdir -p /var/lib/samba/private /var/lib/pk95file /srv/files /var/log/samba \
	# smbd resolves domain users through NSS (rid-mapped Unix IDs).
	&& sed -i -E 's/^(passwd|group):.*/\1:         files winbind/' /etc/nsswitch.conf \
	&& grep -q '^passwd:.*winbind' /etc/nsswitch.conf

COPY pk95file /opt/pk95file/pk95file
# smb.conf "dfree command": the soft quota as disk size (docs/design.md §8)
RUN mkdir -p /opt/pk95file/bin \
	&& printf '#!/bin/sh\nexec python3 -m pk95file.dfree "$@"\n' > /opt/pk95file/bin/dfree \
	&& chmod 755 /opt/pk95file/bin/dfree

ARG VERSION=1.0.1
ENV PYTHONPATH=/opt/pk95file \
	PYTHONUNBUFFERED=1 \
	PYTHONDONTWRITEBYTECODE=1 \
	PK95FILE_VERSION=${VERSION} \
	PK95FILE_LISTEN=0.0.0.0:8445 \
	PK95FILE_DATA_DIR=/var/lib/pk95file \
	PK95FILE_DATA_ROOT=/srv/files

# Maschinenkonto (secrets.tdb), generierte smb.conf und App-Daten überstehen ein neues Image.
# /srv/files ist ein Bind-Mount (Proxmox-Mountpoint), kein Volume: Core sichert ihn nicht mit.
VOLUME ["/var/lib/samba", "/etc/samba", "/var/lib/pk95file"]
EXPOSE 8445 445
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/bin/tini", "--", "python3", "-m", "pk95file"]
