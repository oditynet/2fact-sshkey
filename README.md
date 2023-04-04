This is a PAM module for 2fact auth of sshkey on USB
Enter User\password and enter USB with private key.

```sed
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
