PREFIX ?= /usr/local
ETC ?= /etc
FAIL2BAN_ETC ?= $(ETC)/fail2ban
BIN_DIR := $(PREFIX)/bin

.PHONY: install uninstall reload test

install:
	@echo "[install] Installing script and configuration to system..."
	install -Dm755 bin/fail2ban-telegram.py $(BIN_DIR)/fail2ban-telegram.py
	install -Dm644 config/telegram.conf $(FAIL2BAN_ETC)/telegram.conf
	install -Dm644 action.d/telegram.conf $(FAIL2BAN_ETC)/action.d/telegram.conf
	@$(MAKE) reload

uninstall:
	@echo "[uninstall] Removing script and configuration (jail config is kept)..."
	-rm -f $(BIN_DIR)/fail2ban-telegram.py
	-rm -f $(FAIL2BAN_ETC)/telegram.conf
	-rm -f $(FAIL2BAN_ETC)/action.d/telegram.conf
	@$(MAKE) reload || true

reload:
	@echo "[reload] Reloading fail2ban..."
	-systemctl reload fail2ban 2>/dev/null || systemctl restart fail2ban

# Simple test: call the script directly to send a Telegram ban test notification
# NOTE: this really sends a message to your configured chat
 test:
	/usr/local/bin/fail2ban-telegram.py ban 1.2.3.4 test-jail 600
