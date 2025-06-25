import atexit
import logging
import signal
import threading
from typing import List, Optional

import iptc


class IptablesManager:
    """Manages iptables rules for TCP traffic redirection."""

    def __init__(self, proxy_port: int = 8080, logger: Optional[logging.Logger] = None):
        self.proxy_port = proxy_port
        self.rules_added: List[dict] = []  # Store rule info for cleanup
        self.lock = threading.RLock()
        self.logger = logger or logging.getLogger(__name__)
        self._setup_signal_handlers()
        self._setup_atexit()

        self.logger.debug(f"IptablesManager initialized - Proxy port: {proxy_port}")

    def _setup_signal_handlers(self):
        """Set up signal handlers for graceful cleanup."""

        def signal_handler(signum, frame):
            self.logger.debug(f"Received signal {signum}, cleaning up iptables rules")
            self.cleanup()
            exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        self.logger.debug("Signal handlers set up for iptables cleanup")

    def _setup_atexit(self):
        """Set up atexit handler for cleanup."""
        atexit.register(self.cleanup)
        self.logger.debug("Atexit handler registered for iptables cleanup")

    def setup(self):
        """Set up iptables rules to redirect TCP traffic to local proxy."""
        with self.lock:
            try:
                self.logger.debug("Setting up iptables rules...")

                # Check if we're running as root
                if not self._check_root():
                    raise PermissionError(
                        "This script must be run as root or with sudo"
                    )

                # Add DNAT rule to redirect outgoing TCP to local proxy
                self.logger.debug("Adding DNAT rule...")
                self._add_dnat_rule()

                # Add INPUT rule to allow traffic to proxy
                self.logger.debug("Adding INPUT rule...")
                self._add_input_rule()

                # Add SNAT rule for return traffic
                self.logger.debug("Adding SNAT rule...")
                self._add_snat_rule()

                self.logger.info(
                    f"iptables rules configured successfully (proxy port: {self.proxy_port})"
                )
                self.logger.debug(f"Total rules added: {len(self.rules_added)}")

            except Exception as e:
                self.logger.error(f"Failed to set up iptables rules: {e}")
                self.cleanup()
                raise Exception(f"Failed to set up iptables rules: {e}")

    def _check_root(self) -> bool:
        """Check if running as root."""
        try:
            import os

            is_root = os.geteuid() == 0
            self.logger.debug(f"Running as root: {is_root}")
            return is_root
        except AttributeError:
            # Windows or other non-Unix system
            self.logger.debug("Non-Unix system, skipping root check")
            return True

    def _add_dnat_rule(self):
        """Add DNAT rule to redirect outgoing TCP to local proxy."""
        self.logger.debug("Creating DNAT rule for TCP traffic redirection")

        table = iptc.Table(iptc.Table.NAT)
        chain = iptc.Chain(table, "OUTPUT")

        # Create rule to redirect all TCP traffic
        # Note: We'll handle the proxy port exclusion in the tunnel logic
        rule = iptc.Rule()
        rule.protocol = "tcp"

        rule.target = iptc.Target(rule, "DNAT")
        rule.target.to_destination = f"127.0.0.1:{self.proxy_port}"

        chain.insert_rule(rule)
        self.rules_added.append(
            {"table": iptc.Table.NAT, "chain": "OUTPUT", "rule": rule}
        )
        self.logger.info("Added DNAT rule: redirect all outgoing TCP to local proxy")

    def _add_input_rule(self):
        """Add INPUT rule to allow traffic to proxy."""
        self.logger.debug("Creating INPUT rule to allow proxy traffic")

        table = iptc.Table(iptc.Table.FILTER)
        chain = iptc.Chain(table, "INPUT")
        rule = iptc.Rule()
        rule.protocol = "tcp"
        rule.in_interface = "lo"

        match = rule.create_match("tcp")
        match.dport = str(self.proxy_port)

        rule.target = iptc.Target(rule, "ACCEPT")

        chain.insert_rule(rule)
        self.rules_added.append(
            {"table": iptc.Table.FILTER, "chain": "INPUT", "rule": rule}
        )
        self.logger.info("Added INPUT rule: allow traffic to proxy")

    def _add_snat_rule(self):
        """Add SNAT rule for return traffic."""
        self.logger.debug("Creating SNAT rule for return traffic")

        table = iptc.Table(iptc.Table.NAT)
        chain = iptc.Chain(table, "POSTROUTING")
        rule = iptc.Rule()
        rule.protocol = "tcp"
        rule.src = "127.0.0.1"

        match = rule.create_match("tcp")
        match.sport = str(self.proxy_port)

        rule.target = iptc.Target(rule, "SNAT")
        rule.target.to_source = "0.0.0.0"

        chain.insert_rule(rule)
        self.rules_added.append(
            {"table": iptc.Table.NAT, "chain": "POSTROUTING", "rule": rule}
        )
        self.logger.info("Added SNAT rule: masquerade proxy responses")

    def cleanup(self):
        """Remove all added iptables rules."""
        with self.lock:
            if not self.rules_added:
                self.logger.debug("No iptables rules to clean up")
                return

            self.logger.info("Cleaning up iptables rules...")
            self.logger.debug(f"Removing {len(self.rules_added)} rules")

            # Remove rules in reverse order
            for i, rule_info in enumerate(reversed(self.rules_added)):
                table = iptc.Table(rule_info["table"])
                chain = iptc.Chain(table, rule_info["chain"])
                try:
                    chain.delete_rule(rule_info["rule"])
                    self.logger.info(
                        f"Removed rule from {rule_info['table']}:{rule_info['chain']}"
                    )
                    self.logger.debug(
                        f"Removed rule {len(self.rules_added) - i}/{len(self.rules_added)}"
                    )
                except Exception as e:
                    self.logger.warning(
                        f"Failed to remove rule from {rule_info['table']}:{rule_info['chain']}: {e}"
                    )

            self.rules_added.clear()
            self.logger.info("iptables cleanup completed")
            self.logger.debug("All iptables rules removed successfully")

    def get_rules_info(self) -> List[str]:
        """Get information about added rules."""
        with self.lock:
            info = []
            for i, rule_info in enumerate(self.rules_added):
                rule_desc = (
                    f"{rule_info['table']}:{rule_info['chain']} -> {rule_info['rule']}"
                )
                info.append(rule_desc)
                self.logger.debug(f"Rule {i+1}: {rule_desc}")
            return info

    def get_current_rules(self) -> dict:
        """Get current iptables rules for debugging."""
        try:
            self.logger.debug("Getting current iptables rules for debugging")

            # Get NAT table rules
            nat_table = iptc.Table(iptc.Table.NAT)
            nat_rules = {}
            for chain_name in ["OUTPUT", "POSTROUTING"]:
                try:
                    chain = iptc.Chain(nat_table, chain_name)
                    nat_rules[chain_name] = [str(rule) for rule in chain.rules]
                    self.logger.debug(
                        f"NAT {chain_name} rules: {len(nat_rules[chain_name])}"
                    )
                except Exception as e:
                    self.logger.debug(f"Error getting NAT {chain_name} rules: {e}")
                    nat_rules[chain_name] = []

            # Get FILTER table rules
            filter_table = iptc.Table(iptc.Table.FILTER)
            filter_rules = {}
            try:
                chain = iptc.Chain(filter_table, "INPUT")
                filter_rules["INPUT"] = [str(rule) for rule in chain.rules]
                self.logger.debug(f"FILTER INPUT rules: {len(filter_rules['INPUT'])}")
            except Exception as e:
                self.logger.debug(f"Error getting FILTER INPUT rules: {e}")
                filter_rules["INPUT"] = []

            current_rules = {
                "nat": nat_rules,
                "filter": filter_rules,
                "our_rules_count": len(self.rules_added),
            }

            self.logger.debug(f"Current iptables state: {current_rules}")
            return current_rules

        except Exception as e:
            self.logger.error(f"Error getting current iptables rules: {e}")
            return {"error": str(e)}

    def is_setup(self) -> bool:
        """Check if iptables rules are set up."""
        with self.lock:
            return len(self.rules_added) > 0
