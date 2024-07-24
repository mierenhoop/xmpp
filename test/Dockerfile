from debian:bookworm
run apt-get update && \
    apt-get install -y prosody && \
    apt-get clean
copy prosody.cfg.lua /etc/prosody/
copy localhost.* /var/lib/prosody/
expose 5222
workdir /var/lib/prosody
user prosody
run prosodyctl register admin localhost adminpass
run prosodyctl register user localhost userpass
cmd /usr/bin/prosody -F
