FROM kalilinux/kali-rolling@sha256:69a9a33d98a584a537bd0f7144d20c3b6d23f3bafa9ffcf0cadf4c5f186d02ff
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends sslscan whatweb ca-certificates \
 && apt-get clean && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --shell /bin/sh sentinel \
 && printf '[user]\ndefault=sentinel\n[interop]\nenabled=false\nappendWindowsPath=false\n[boot]\nsystemd=false\n' > /etc/wsl.conf \
 && printf 'sentinel-kali-tools-v1\n' > /etc/sentinel-toolkit \
 && command -v timeout && sslscan --version && whatweb --version
