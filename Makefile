PREFIX ?= /usr/local
ETC ?= /etc
FAIL2BAN_ETC ?= $(ETC)/fail2ban
BIN_DIR := $(PREFIX)/bin

.PHONY: install uninstall reload test check verify-config

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

# Check fail2ban service status
check:
	@echo "[check] Checking fail2ban service status..."
	@systemctl is-active --quiet fail2ban && echo "✓ fail2ban service is running" || (echo "✗ fail2ban service is not running"; exit 1)
	@echo "[check] Checking fail2ban configuration..."
	@fail2ban-client status >/dev/null 2>&1 && echo "✓ fail2ban-client is working" || (echo "✗ fail2ban-client is not working"; exit 1)

# Verify bantime.increment and related configurations
verify-config:
	@echo "[verify-config] Verifying fail2ban bantime settings..."
	@echo ""
	@echo "Checking configuration files:"
	@if [ -f $(FAIL2BAN_ETC)/jail.local ]; then \
		echo "  Checking $(FAIL2BAN_ETC)/jail.local:"; \
		grep -q "^bantime.increment\s*=" $(FAIL2BAN_ETC)/jail.local 2>/dev/null && \
			VALUE=$$(grep "^bantime.increment\s*=" $(FAIL2BAN_ETC)/jail.local | head -1 | sed 's/.*=\s*//' | tr -d ' ') && \
			echo "    ✓ bantime.increment = $${VALUE}" || \
			echo "    ✗ bantime.increment is not set"; \
		grep -q "^bantime.factor\s*=" $(FAIL2BAN_ETC)/jail.local 2>/dev/null && \
			VALUE=$$(grep "^bantime.factor\s*=" $(FAIL2BAN_ETC)/jail.local | head -1 | sed 's/.*=\s*//' | tr -d ' ') && \
			echo "    ✓ bantime.factor = $${VALUE}" || \
			echo "    ✗ bantime.factor is not set"; \
		grep -q "^bantime.multipliers\s*=" $(FAIL2BAN_ETC)/jail.local 2>/dev/null && \
			VALUE=$$(grep "^bantime.multipliers\s*=" $(FAIL2BAN_ETC)/jail.local | head -1 | sed 's/.*=\s*//') && \
			echo "    ✓ bantime.multipliers = $${VALUE}" || \
			echo "    ✗ bantime.multipliers is not set"; \
		grep -q "^bantime.formula\s*=" $(FAIL2BAN_ETC)/jail.local 2>/dev/null && \
			VALUE=$$(grep "^bantime.formula\s*=" $(FAIL2BAN_ETC)/jail.local | head -1 | sed 's/.*=\s*//' | head -c 60) && \
			echo "    ✓ bantime.formula = $${VALUE}..." || \
			echo "    ✗ bantime.formula is not set"; \
	else \
		echo "  ✗ $(FAIL2BAN_ETC)/jail.local not found"; \
	fi
	@echo ""
	@echo "Checking active jails:"
	@JAILS=$$(fail2ban-client status 2>/dev/null | grep "Jail list:" | cut -d: -f2 | tr ',' ' '); \
	for jail in $${JAILS}; do \
		jail=$$(echo $${jail} | xargs); \
		[ -z "$${jail}" ] && continue; \
		echo "  Jail: $${jail}"; \
		fail2ban-client get "$${jail}" bantime >/dev/null 2>&1 && \
			VALUE=$$(fail2ban-client get "$${jail}" bantime 2>/dev/null) && \
			echo "    ✓ bantime = $${VALUE} seconds" || \
			echo "    ✗ bantime is not set"; \
		fail2ban-client get "$${jail}" maxretry >/dev/null 2>&1 && \
			VALUE=$$(fail2ban-client get "$${jail}" maxretry 2>/dev/null) && \
			echo "    ✓ maxretry = $${VALUE}" || \
			echo "    - maxretry not queried"; \
	done
	@echo ""
	@echo "[verify-config] Configuration verification completed."
