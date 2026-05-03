class SummaryEngine:
    @staticmethod
    def generate_executive_summary(scan_results, graph, paths, risk, cost):
        """
        Generates a high-level executive summary based on the current infrastructure state.
        """
        is_secure = len(paths) == 0
        
        # Determine Status and Base Summary
        if is_secure:
            status = "SECURE"
            summary = "No exploitable attack chains detected. Infrastructure follows secure configuration."
        else:
            status = "AT RISK"
            summary = f"System compromised. {len(paths)} active attack paths detected that could lead to data exfiltration or resource exploitation."

        # Key Points (Insights)
        key_points = []
        public_ec2 = [item for item in scan_results.get('ec2', []) if item.get('is_public')]
        admin_iam = [item for item in scan_results.get('iam', []) if item.get('is_admin')]
        public_s3 = [item for item in scan_results.get('s3', []) if item.get('is_public')]

        if not public_ec2:
            key_points.append("No public EC2 exposure")
        else:
            key_points.append(f"{len(public_ec2)} EC2 instances are publicly exposed")

        if not admin_iam:
            key_points.append("IAM privileges are restricted")
        else:
            key_points.append(f"{len(admin_iam)} identities have administrative privileges")

        if not public_s3:
            key_points.append("No reachable sensitive storage")
        else:
            key_points.append(f"{len(public_s3)} S3 buckets have public access enabled")

        # Warnings (Watchlist)
        warnings = []
        if admin_iam:
            warnings.append(f"{len(admin_iam)} IAM role(s) have elevated permissions (monitor recommended)")
        
        # Check for unused/old resources if possible (simplified for now)
        if len(scan_results.get('ec2', [])) > 5:
            warnings.append("High number of active EC2 instances (review usage)")

        # Recommendations
        recommendations = []
        if is_secure:
            recommendations.append("Enable continuous monitoring")
            recommendations.append("Audit IAM roles periodically")
        else:
            recommendations.append("Remediate public EC2 exposures immediately")
            recommendations.append("Enforce Least Privilege for admin roles")
            recommendations.append("Block public access on S3 buckets")

        # Simulation Insight
        simulation_insight = "No immediate threat scenario detected."
        if admin_iam:
            simulation_insight = "If an attacker gains access to a privileged IAM role, they could potentially access all sensitive resources."
        elif public_ec2:
            simulation_insight = "An attacker could use a public EC2 instance as a bridgehead to scan your internal network."

        return {
            "status": status,
            "summary": summary,
            "key_points": key_points,
            "warnings": warnings if warnings else ["No immediate warnings detected."],
            "recommendations": recommendations,
            "simulation_insight": simulation_insight,
            "attack_surface": {
                "public_resources": len(public_ec2) + len(public_s3),
                "privileged_identities": len(admin_iam),
                "sensitive_assets": len(scan_results.get('s3', []))
            }
        }
