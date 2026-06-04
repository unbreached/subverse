"""Subverse — full DNS + service probe and attack-surface visualizer.

Feed it a list of (sub)domains; it resolves DNS, identifies hosting providers
and nameservers, fingerprints exposed services with nmap, and renders both an
interactive HTML graph and a static image so forgotten/stale hosts stand out.
"""

__version__ = "0.1.0"
