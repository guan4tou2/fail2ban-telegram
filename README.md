# Fail2ban Telegram Notifier

Maintain all Fail2ban Telegram notification scripts and configs in one place,
and provide a `Makefile` for quick deployment to the system.

## Structure

- `bin/fail2ban-telegram.py`: main notification script (installed to `/usr/local/bin/fail2ban-telegram.py`)
- `config/telegram.conf`: Telegram bot / chat / options configuration (installed to `/etc/fail2ban/telegram.conf`)
- `action.d/telegram.conf`: Fail2ban action definition (installed to `/etc/fail2ban/action.d/telegram.conf`)
- `Makefile`: install / uninstall / reload / test targets

## Usage

> Run the following commands as `root` (or via `sudo`).

### Install / update into the system

```bash
cd /root/fail2ban-telegram
make install
```

This will:

- Install `bin/fail2ban-telegram.py` to `/usr/local/bin/fail2ban-telegram.py`
- Install `config/telegram.conf` to `/etc/fail2ban/telegram.conf`
- Install `action.d/telegram.conf` to `/etc/fail2ban/action.d/telegram.conf`
- Automatically reload / restart `fail2ban`

### Uninstall (keeps your jail.local / jail.d config)

```bash
cd /root/fail2ban-telegram
make uninstall
```

This removes:

- `/usr/local/bin/fail2ban-telegram.py`
- `/etc/fail2ban/telegram.conf`
- `/etc/fail2ban/action.d/telegram.conf`

### Test that the script can send a Telegram notification

```bash
cd /root/fail2ban-telegram
make test
```

This directly calls the script to send a ban test message to the chat
configured in `telegram.conf`.

### Check fail2ban service status

```bash
cd /root/fail2ban-telegram
make check
```

This checks if the fail2ban service is running and if fail2ban-client is working.

### Verify bantime.increment and related configurations

```bash
cd /root/fail2ban-telegram
make verify-config
```

This verifies that bantime.increment, bantime.factor, bantime.multipliers, and
bantime.formula are properly configured in `/etc/fail2ban/jail.local`, and
displays the current bantime and maxretry settings for active jails.

### Integrate with psad (Port Scan Attack Detector)

You can have psad call this Telegram script directly when it detects a port
scan by enabling psad's external script support and pointing it at
`fail2ban-telegram.py`:

1. Edit `/etc/psad/psad.conf` and set:

   ```text
   ENABLE_EXT_SCRIPT_EXEC      Y;
   EXTERNAL_SCRIPT             /usr/local/bin/fail2ban-telegram.py psad SRCIP;
   EXEC_EXT_SCRIPT_PER_ALERT   Y;
   ```

   The `SRCIP` token will be replaced by the attacker source IP. The script
   will resolve geo information for that IP and send a PSAD alert to Telegram.

2. Reload / restart psad so the changes take effect, for example:

   ```bash
   sudo systemctl restart psad
   # or (depending on your distro)
   sudo psad -R
   ```

> IMPORTANT: this project does **not** automatically modify your `jail.local`
> or `jail.d/*.conf`. Jails such as `sshd` still need to be configured manually
> with `action = %(action_)s` and `telegram[...]`.
