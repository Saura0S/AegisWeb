"""
Automated Patch & Configuration Code Generator Module
Synthesizes ready-to-paste configuration fixes for Nginx, Apache, and .htaccess.
"""

from typing import List, Dict, Any


class PatchGenerator:
    """Generates server configuration code snippets to resolve detected security gaps."""

    def generate_nginx_config(self, missing_headers: List[Dict[str, Any]]) -> str:
        """Generate Nginx server block snippet."""
        lines = [
            "# ====================================================================",
            "# AegisWeb Auto-Generated Security Configuration for Nginx (nginx.conf)",
            "# Paste these lines inside your server { ... } block and reload Nginx.",
            "# ====================================================================",
            ""
        ]
        for h in missing_headers:
            if "nginx_patch" in h:
                lines.append(f"    {h['nginx_patch']}")
        
        lines.append("    server_tokens off; # Mask Nginx server version")
        return "\n".join(lines)

    def generate_apache_config(self, missing_headers: List[Dict[str, Any]]) -> str:
        """Generate Apache / .htaccess snippet."""
        lines = [
            "# ====================================================================",
            "# AegisWeb Auto-Generated Security Configuration for Apache (.htaccess)",
            "# Paste these lines into your .htaccess or VirtualHost directive.",
            "# ====================================================================",
            "<IfModule mod_headers.c>"
        ]
        for h in missing_headers:
            if "apache_patch" in h:
                lines.append(f"    {h['apache_patch']}")
        
        lines.append("    Header unset Server")
        lines.append("    Header unset X-Powered-By")
        lines.append("</IfModule>")
        lines.append("ServerSignature Off")
        lines.append("ServerTokens Prod")
        return "\n".join(lines)