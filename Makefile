PREFIX ?= /usr/local
ETC ?= /etc
FAIL2BAN_ETC ?= $(ETC)/fail2ban
BIN_DIR := $(PREFIX)/bin
SCRIPT := $(BIN_DIR)/fail2ban-telegram.py
ACTION_NAME ?= telegram-sshd
JAIL ?= sshd
PSAD_CONF ?= /etc/psad/psad.conf

.PHONY: help install uninstall reload restart test check check-telegram verify-config verify-actions psad-enable psad-disable psad-reload verify-psad psad-test

help:
	@echo "Targets:"
	@echo "  make install           Install script and fail2ban telegram configs"
	@echo "  make uninstall         Remove installed script/config files"
	@echo "  make reload            Reload fail2ban (restart jails if needed)"
	@echo "  make restart           Restart fail2ban service"
	@echo "  make test              Send a test ban notification to Telegram"
	@echo "  make check             Check fail2ban service/client status"
	@echo "  make check-telegram    Verify Telegram bot connectivity"
	@echo "  make verify-config     Verify bantime-related configuration"
	@echo "  make verify-actions    Verify current jail has telegram action"
	@echo "  make psad-enable       Enable psad -> Telegram script hook"
	@echo "  make psad-disable      Disable psad external script execution"
	@echo "  make psad-reload       Reload/restart psad service"
	@echo "  make verify-psad       Verify psad hook configuration"
	@echo "  make psad-test         Send a synthetic psad alert to Telegram"
	@echo ""
	@echo "Variables:"
	@echo "  JAIL=<name>            Jail name for verify-actions (default: sshd)"
	@echo "  ACTION_NAME=<name>     Telegram action name hint (default: telegram-sshd)"
	@echo "  PSAD_CONF=<path>       psad config path (default: /etc/psad/psad.conf)"

install:
	@echo "[install] Installing script and configuration to system..."
	install -Dm755 bin/fail2ban-telegram.py $(SCRIPT)
	install -Dm644 config/telegram.conf $(FAIL2BAN_ETC)/telegram.conf
	install -Dm644 action.d/telegram.conf $(FAIL2BAN_ETC)/action.d/telegram.conf
	@$(MAKE) reload

uninstall:
	@echo "[uninstall] Removing script and configuration (jail config is kept)..."
	-rm -f $(SCRIPT)
	-rm -f $(FAIL2BAN_ETC)/telegram.conf
	-rm -f $(FAIL2BAN_ETC)/action.d/telegram.conf
	@$(MAKE) reload || true

reload:
	@echo "[reload] Reloading fail2ban..."
	@fail2ban-client reload --restart >/dev/null 2>&1 || \
		systemctl reload fail2ban >/dev/null 2>&1 || \
		systemctl restart fail2ban

restart:
	@echo "[restart] Restarting fail2ban..."
	@systemctl restart fail2ban

# Simple test: call the script directly to send a Telegram ban test notification
# NOTE: this really sends a message to your configured chat
test:
	$(SCRIPT) ban 1.2.3.4 test-jail 600

# Check fail2ban service status
check:
	@echo "[check] Checking fail2ban service status..."
	@systemctl is-active --quiet fail2ban && echo "✓ fail2ban service is running" || (echo "✗ fail2ban service is not running"; exit 1)
	@echo "[check] Checking fail2ban configuration..."
	@fail2ban-client status >/dev/null 2>&1 && echo "✓ fail2ban-client is working" || (echo "✗ fail2ban-client is not working"; exit 1)

check-telegram:
	@echo "[check-telegram] Checking Telegram bot connectivity..."
	@$(SCRIPT) check >/dev/null 2>&1 && echo "✓ Telegram bot connectivity OK" || (echo "✗ Telegram bot connectivity failed"; exit 1)

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

verify-actions:
	@echo "[verify-actions] Checking fail2ban actions for jail: $(JAIL)"
	@ACTIONS=$$(fail2ban-client get "$(JAIL)" actions 2>/dev/null || true); \
	if [ -z "$$ACTIONS" ]; then \
		echo "  ✗ unable to read actions for jail: $(JAIL)"; \
		exit 1; \
	fi; \
	echo "  $$ACTIONS"; \
	echo "$$ACTIONS" | grep -qi "telegram" && \
		echo "  ✓ telegram action is loaded" || \
		(echo "  ✗ telegram action not found"; \
		 echo "    hint: ensure jail action includes telegram[name=$(ACTION_NAME)] then run 'make reload'"; \
		 exit 1)

psad-enable:
	@echo "[psad-enable] Enabling psad external script hook..."
	@if [ ! -f "$(PSAD_CONF)" ]; then \
		echo "✗ $(PSAD_CONF) not found"; \
		exit 1; \
	fi
	@BACKUP="$(PSAD_CONF).bak.$$(date +%Y%m%d%H%M%S)"; \
	cp -a "$(PSAD_CONF)" "$$BACKUP"; \
	echo "  backup: $$BACKUP"
	@sed -Ei 's|^[[:space:]]*ENABLE_EXT_SCRIPT_EXEC[[:space:]]+.*;|ENABLE_EXT_SCRIPT_EXEC      Y;|' "$(PSAD_CONF)"
	@sed -Ei 's|^[[:space:]]*EXEC_EXT_SCRIPT_PER_ALERT[[:space:]]+.*;|EXEC_EXT_SCRIPT_PER_ALERT   Y;|' "$(PSAD_CONF)"
	@sed -Ei 's|^[[:space:]]*EXTERNAL_SCRIPT[[:space:]]+.*;|EXTERNAL_SCRIPT             $(SCRIPT) psad SRCIP;|' "$(PSAD_CONF)"
	@grep -Eq '^[[:space:]]*ENABLE_EXT_SCRIPT_EXEC[[:space:]]+' "$(PSAD_CONF)" || echo 'ENABLE_EXT_SCRIPT_EXEC      Y;' >>"$(PSAD_CONF)"
	@grep -Eq '^[[:space:]]*EXEC_EXT_SCRIPT_PER_ALERT[[:space:]]+' "$(PSAD_CONF)" || echo 'EXEC_EXT_SCRIPT_PER_ALERT   Y;' >>"$(PSAD_CONF)"
	@grep -Eq '^[[:space:]]*EXTERNAL_SCRIPT[[:space:]]+' "$(PSAD_CONF)" || echo 'EXTERNAL_SCRIPT             $(SCRIPT) psad SRCIP;' >>"$(PSAD_CONF)"
	@$(MAKE) psad-reload

psad-disable:
	@echo "[psad-disable] Disabling psad external script execution..."
	@if [ ! -f "$(PSAD_CONF)" ]; then \
		echo "✗ $(PSAD_CONF) not found"; \
		exit 1; \
	fi
	@BACKUP="$(PSAD_CONF).bak.$$(date +%Y%m%d%H%M%S)"; \
	cp -a "$(PSAD_CONF)" "$$BACKUP"; \
	echo "  backup: $$BACKUP"
	@sed -Ei 's|^[[:space:]]*ENABLE_EXT_SCRIPT_EXEC[[:space:]]+.*;|ENABLE_EXT_SCRIPT_EXEC      N;|' "$(PSAD_CONF)"
	@sed -Ei 's|^[[:space:]]*EXEC_EXT_SCRIPT_PER_ALERT[[:space:]]+.*;|EXEC_EXT_SCRIPT_PER_ALERT   N;|' "$(PSAD_CONF)"
	@$(MAKE) psad-reload

psad-reload:
	@echo "[psad-reload] Reloading/restarting psad..."
	@systemctl reload psad >/dev/null 2>&1 || \
		systemctl restart psad >/dev/null 2>&1 || \
		psad -R >/dev/null 2>&1 || \
		(echo "✗ unable to reload psad"; exit 1)
	@echo "✓ psad reloaded"

verify-psad:
	@echo "[verify-psad] Checking psad integration..."
	@if [ ! -f "$(PSAD_CONF)" ]; then \
		echo "✗ $(PSAD_CONF) not found"; \
		exit 1; \
	fi
	@grep -E '^[[:space:]]*ENABLE_EXT_SCRIPT_EXEC[[:space:]]+' "$(PSAD_CONF)" | tail -1 | sed 's/^/  /'
	@grep -E '^[[:space:]]*EXEC_EXT_SCRIPT_PER_ALERT[[:space:]]+' "$(PSAD_CONF)" | tail -1 | sed 's/^/  /'
	@grep -E '^[[:space:]]*EXTERNAL_SCRIPT[[:space:]]+' "$(PSAD_CONF)" | tail -1 | sed 's/^/  /'
	@grep -Eq '^[[:space:]]*ENABLE_EXT_SCRIPT_EXEC[[:space:]]+Y;' "$(PSAD_CONF)" && \
	 grep -Eq '^[[:space:]]*EXEC_EXT_SCRIPT_PER_ALERT[[:space:]]+Y;' "$(PSAD_CONF)" && \
	 grep -Eq "^[[:space:]]*EXTERNAL_SCRIPT[[:space:]]+$(SCRIPT)[[:space:]]+psad[[:space:]]+SRCIP;" "$(PSAD_CONF)" && \
		echo "✓ psad hook configuration looks correct" || \
		(echo "✗ psad hook configuration is incomplete"; exit 1)

psad-test:
	@echo "[psad-test] Sending synthetic psad alert to Telegram..."
	@$(SCRIPT) psad 198.51.100.10 203.0.113.10 22 tcp 5
