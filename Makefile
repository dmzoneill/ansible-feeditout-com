# Makefile for Ansible Server Cloning Project

INVENTORY_REMOTE ?= inventories/hosts_avoro.ini
INVENTORY_LOCAL ?= inventories/hosts_local.ini
VAULT_OPTS ?=  --vault-password-file ~/.ansible-vault-pass
VERBOSITY ?=  -v

.PHONY: all ping ensure-dave copy-dave test-sudo base-packages sync-services sync-mail harden-ssh sync-cron sync-mariadb reboot-new full-migration reconcile backup-old super-lint migrated-sync-mariadb

all: base-packages

old-backup:
	ansible-playbook $(VERBOSITY) -i $(INVENTORY_REMOTE) playbooks/old_backup.yml $(VAULT_OPTS)

base-packages:
	ansible-playbook $(VERBOSITY) -i $(INVENTORY_REMOTE) playbooks/migrate_base_packages.yml $(VAULT_OPTS)

ping:
	ansible $(VERBOSITY) -i $(INVENTORY_REMOTE) all -m ping $(VAULT_OPTS)

new-ssh-key:
	ansible-playbook $(VERBOSITY) -i $(INVENTORY_REMOTE) playbooks/migrate_ssh_key.yml $(VAULT_OPTS)

test-sudo:
	ansible-playbook $(VERBOSITY) -i $(INVENTORY_REMOTE) playbooks/migrate_test_sudo.yml $(VAULT_OPTS)

ensure-dave:
	ansible-playbook $(VERBOSITY) -i $(INVENTORY_REMOTE) playbooks/migrate_ensure_dave.yml $(VAULT_OPTS)

copy-dave:
	ansible-playbook $(VERBOSITY) -i $(INVENTORY_REMOTE) playbooks/migrate_sync_home_dave.yml $(VAULT_OPTS)

sync-services:
	ansible-playbook $(VERBOSITY) -i $(INVENTORY_REMOTE) playbooks/migrate_sync_services.yml $(VAULT_OPTS)

sync-mail:
	ansible-playbook $(VERBOSITY) -i $(INVENTORY_REMOTE) playbooks/migrate_sync_mailboxes.yml $(VAULT_OPTS)

harden-ssh:
	ansible-playbook $(VERBOSITY) -i $(INVENTORY_REMOTE) playbooks/migrate_harden_ssh.yml $(VAULT_OPTS)

sync-mariadb:
	ansible-playbook $(VERBOSITY) -i $(INVENTORY_REMOTE) playbooks/migrate_sync_maria_db.yml $(VAULT_OPTS)

reboot-new:
	ansible-playbook $(VERBOSITY) -i $(INVENTORY_REMOTE) playbooks/migrate_reboot_new.yml $(VAULT_OPTS)

migrated-sync-mariadb:
	ansible-playbook $(VERBOSITY) -i $(INVENTORY_REMOTE) playbooks/migrate_sync_maria_db.yml $(VAULT_OPTS)

full-migration:
	@echo "Starting full setup process..."
	- $(MAKE) ping
	$(MAKE) new-ssh-key
	$(MAKE) ensure-dave
	$(MAKE) copy-dave
	$(MAKE) test-sudo
	$(MAKE) base-packages
	$(MAKE) sync-services
	$(MAKE) sync-mariadb
	$(MAKE) sync-mail
	- $(MAKE) harden-ssh
	- $(MAKE) reboot-new
	- $(MAKE) reconcile

reconcile:
	ansible-playbook $(VERBOSITY) -i $(INVENTORY_REMOTE) playbooks/reconcile.yml $(VAULT_OPTS)


ansible-pull:
	ansible-playbook $(VERBOSITY) -i $(INVENTORY_LOCAL) playbooks/ansible-pull.yml $(VAULT_OPTS)

super-lint:
	docker run --rm \
	-e SUPER_LINTER_LINTER=error \
	-e LINTER_OUTPUT=error \
	-e LOG_LEVEL=ERROR \
	-e RUN_LOCAL=true \
	-e FILTER_REGEX_EXCLUDE="(^|/)\.git(/|$)|(^|/)backups(/|$)|(^|/)roles/[^/]+/files(/|/)" \
	-e GIT_IGNORE=true \
	-v $$(pwd):/tmp/lint \
	-w /tmp/lint \
	github/super-linter:latest --quiet

lint:
	find playbooks/ -type f -iname "*.yml" -exec yamllint {} \;
	find inventories/ -type f -iname "*.yml" -exec yamllint {} \;
	find roles/ -type f -iname "*.yml" -exec yamllint {} \;
	find host_vars/ -type f -iname "*.yml" -exec yamllint {} \;
	find group_vars/ -type f -iname "*.yml" -exec yamllint {} \;

ansible-lint:
	find playbooks/ -type f -iname "*.yml" -exec ansible-lint {} \;
	find inventories/ -type f -iname "*.yml" -exec ansible-lint {} \;
	find roles/ -type f -iname "*.yml" -exec ansible-lint {} \;
	find host_vars/ -type f -iname "*.yml" -exec ansible-lint {} \;
	find group_vars/ -type f -iname "*.yml" -exec ansible-lint {} \;