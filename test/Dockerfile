from debian:bookworm
run apt-get update && \
    apt-get install -y prosody && \
    apt-get clean
copy prosody.cfg.lua /etc/prosody/
run echo -e "\n\n\n" | prosodyctl cert generate localhost
expose 5222
workdir /var/lib/prosody
cmd /usr/bin/prosody -F
