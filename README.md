This is a PAM module for 2fact auth of sshkey on USB

Enter User\password and enter USB with private key.

Your are generate a key with ssh-keygen. Private key copy to USB flash with ext4 FS, public key copy to /root or etc. (edit a code)

```sed
systemcctl start sshd (add :
PubkeyAuthentication yes
PubkeyAcceptedKeyTypes=+ssh-rsa)

cp usb-mount@.service /etc/systemd/system/
cp 35-auth.rules /etc/udev/rules.d/
cp usb-mount.sh /usr/local/bin/
chmod u+x /usr/local/bin/usb-mount.sh
udevadm control --reload-rules
systemctl daemon-reload
make
cp 2fact.so /usr/lib/security
```
add to /etc/pam.d/system-auth "auth	requisite	2fact.so"

TODO:
 - Do not used a sshd service
