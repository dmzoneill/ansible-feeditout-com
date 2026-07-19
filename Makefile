# Makefile for Ansible Server Migration & Configuration
#
# Remote targets: run from a workstation against remote hosts
# Local targets:  run on the server itself (localhost)

INVENTORY_REMOTE ?= inventories/hosts_avoro.ini
INVENTORY_LOCAL  ?= inventories/hosts_local.ini
VAULT_OPTS       ?= --vault-password-file ~/.ansible-vault-pass
VERBOSITY        ?= -vvv
ANSIBLE_PLAY     := ansible-playbook $(VERBOSITY)

.PHONY: all help \
        ping old-backup base-packages static-networking new-ssh-key \
        ansible-secret test-sudo ensure-dave copy-dave \
        sync-services sync-mail sync-cron sync-mariadb \
        harden-ssh reboot-new full-migration \
        reconcile reconcile-role reconcile-local reconcile-local-role \
        ansible-pull lint ansible-lint super-lint go-live

all: help

help:
	@echo "Remote targets (run from workstation):"
	@echo "  ping              - Test connectivity to old/new hosts"
	@echo "  old-backup        - Backup old server data"
	@echo "  base-packages     - Install base packages on new server"
	@echo "  sync-services     - Sync service configs from old to new"
	@echo "  sync-mail         - Sync mailboxes from old to new"
	@echo "  sync-cron         - Sync cron jobs from old to new"
	@echo "  sync-mariadb      - Sync MariaDB data from old to new"
	@echo "  harden-ssh        - Apply SSH hardening to new server"
	@echo "  full-migration    - Run complete migration sequence"
	@echo "  reconcile         - Run all roles remotely via SSH"
	@echo "  reconcile-role    - Run a single role remotely (ROLE=name)"
	@echo ""
	@echo "Local targets (run on the server itself):"
	@echo "  reconcile-local      - Run all roles locally"
	@echo "  reconcile-local-role - Run a single role locally (ROLE=name)"
	@echo ""
	@echo "Lint targets:"
	@echo "  lint              - Run yamllint on all YAML files"
	@echo "  ansible-lint      - Run ansible-lint on all YAML files"
	@echo "  super-lint        - Run GitHub super-linter via Docker"

# ---------------------------------------------------------------------------
# Remote targets (workstation → remote hosts via SSH)
# ---------------------------------------------------------------------------

ping:
	ansible $(VERBOSITY) -i $(INVENTORY_REMOTE) old -m ping $(VAULT_OPTS)
	ansible $(VERBOSITY) -i $(INVENTORY_REMOTE) new -m ping $(VAULT_OPTS)

old-backup:
	$(ANSIBLE_PLAY) -i $(INVENTORY_REMOTE) playbooks/old_backup.yml $(VAULT_OPTS)

base-packages:
	$(ANSIBLE_PLAY) -i $(INVENTORY_REMOTE) playbooks/migrate_base_packages.yml $(VAULT_OPTS)

static-networking:
	$(ANSIBLE_PLAY) -i $(INVENTORY_REMOTE) playbooks/migrate_prepare_network.yml $(VAULT_OPTS)

new-ssh-key:
	$(ANSIBLE_PLAY) -i $(INVENTORY_REMOTE) playbooks/migrate_ssh_key.yml $(VAULT_OPTS)

ansible-secret:
	$(ANSIBLE_PLAY) -i $(INVENTORY_REMOTE) playbooks/migrate_ansible_secret.yml $(VAULT_OPTS)

test-sudo:
	$(ANSIBLE_PLAY) -i $(INVENTORY_REMOTE) playbooks/migrate_test_sudo.yml $(VAULT_OPTS)

ensure-dave:
	$(ANSIBLE_PLAY) -i $(INVENTORY_REMOTE) playbooks/migrate_ensure_dave.yml $(VAULT_OPTS)

copy-dave:
	$(ANSIBLE_PLAY) -i $(INVENTORY_REMOTE) playbooks/migrate_sync_home_dave.yml $(VAULT_OPTS)

sync-services:
	$(ANSIBLE_PLAY) -i $(INVENTORY_REMOTE) playbooks/migrate_sync_services.yml $(VAULT_OPTS)

sync-mail:
	$(ANSIBLE_PLAY) -i $(INVENTORY_REMOTE) playbooks/migrate_sync_mailboxes.yml $(VAULT_OPTS)

sync-cron:
	$(ANSIBLE_PLAY) -i $(INVENTORY_REMOTE) playbooks/migrate_sync_cron.yml $(VAULT_OPTS)

sync-mariadb:
	$(ANSIBLE_PLAY) -i $(INVENTORY_REMOTE) playbooks/migrate_sync_maria_db.yml $(VAULT_OPTS)

harden-ssh:
	$(ANSIBLE_PLAY) -i $(INVENTORY_REMOTE) playbooks/migrate_harden_ssh.yml $(VAULT_OPTS)

reboot-new:
	$(ANSIBLE_PLAY) -i $(INVENTORY_REMOTE) playbooks/migrate_reboot_new.yml $(VAULT_OPTS)

reconcile:
	$(ANSIBLE_PLAY) -i $(INVENTORY_REMOTE) playbooks/reconcile.yml $(VAULT_OPTS)

reconcile-role:
	$(ANSIBLE_PLAY) -i $(INVENTORY_REMOTE) playbooks/reconcile.yml --extra-vars "role_to_run=$(ROLE)" $(VAULT_OPTS)

# ---------------------------------------------------------------------------
# Full migration (sequential, some steps allowed to fail)
# ---------------------------------------------------------------------------

full-migration:
	@echo "Starting full migration..."
	-$(MAKE) ping
	$(MAKE) new-ssh-key
	$(MAKE) static-networking
	$(MAKE) ansible-secret
	$(MAKE) ensure-dave
	$(MAKE) copy-dave
	$(MAKE) test-sudo
	$(MAKE) base-packages
	$(MAKE) sync-services
	$(MAKE) sync-cron
	$(MAKE) sync-mariadb
	$(MAKE) sync-mail
	-$(MAKE) harden-ssh
	-$(MAKE) reboot-new
	-$(MAKE) reconcile

# ---------------------------------------------------------------------------
# Local targets (run directly on the managed server)
# ---------------------------------------------------------------------------

reconcile-local:
	$(ANSIBLE_PLAY) -i $(INVENTORY_LOCAL) playbooks/reconcile.yml $(VAULT_OPTS)

reconcile-local-role:
	$(ANSIBLE_PLAY) -i $(INVENTORY_LOCAL) playbooks/reconcile.yml --extra-vars "role_to_run=$(ROLE)" $(VAULT_OPTS)

ansible-pull:
	$(ANSIBLE_PLAY) -i $(INVENTORY_LOCAL) playbooks/ansible-pull.yml $(VAULT_OPTS)

# ---------------------------------------------------------------------------
# Linting
# ---------------------------------------------------------------------------

lint:
	find playbooks/ roles/ host_vars/ group_vars/ inventories/ -type f -iname "*.yml" -exec yamllint {} +

ansible-lint:
	find playbooks/ roles/ host_vars/ group_vars/ inventories/ -type f -iname "*.yml" -exec ansible-lint {} +

super-lint:
	docker run --rm \
		-e SUPER_LINTER_LINTER=error \
		-e LINTER_OUTPUT=error \
		-e LOG_LEVEL=ERROR \
		-e RUN_LOCAL=true \
		-e FILTER_REGEX_EXCLUDE="(^|/)\.git(/|$$)|(^|/)backups(/|$$)|(^|/)roles/[^/]+/files(/|/)" \
		-e GIT_IGNORE=true \
		-v $$(pwd):/tmp/lint \
		-w /tmp/lint \
		github/super-linter:latest --quiet

# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------

go-live:
	-rm -v dns/*bak*
	git add dns/ host_vars/ roles/ playbooks/
	fancy-git-commit
	git pull --rebase
	git push
