# ODJ spike: a minimal Samba domain member (Debian trixie, Samba 4.22), the same packages PK95 File will use.
# Also serves as the test client (kinit + smbclient). Not the product image.
FROM debian:trixie-slim

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
		samba winbind libnss-winbind smbclient krb5-user \
		iproute2 iputils-arping acl attr procps ca-certificates \
	&& rm -rf /var/lib/apt/lists/* \
	&& rm -f /etc/samba/smb.conf \
	# smbd resolves domain users through NSS (getpwuid of the rid-mapped Unix ID).
	&& sed -i -E 's/^(passwd|group):.*/\1:         files winbind/' /etc/nsswitch.conf

CMD ["sleep", "infinity"]
