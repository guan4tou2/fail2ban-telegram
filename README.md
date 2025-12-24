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

> IMPORTANT: this project does **not** automatically modify your `jail.local`
> or `jail.d/*.conf`. Jails such as `sshd` still need to be configured manually
> with `action = %(action_)s` and `telegram[...]`.
