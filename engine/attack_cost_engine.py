class AttackCostEngine:
    @staticmethod
    def simulate_attack_cost(infrastructure, attack_paths):
        """
        Simulates the financial impact of an attacker exploiting AWS resources.
        Scenario: Attacker uses IAM Admin roles to launch instances for crypto mining.
        """
        has_public_ec2 = any(item['type'] == 'EC2' and item['status'] == 'NOT SAFE' for item in infrastructure)
        has_admin_iam = any(item['type'] == 'IAM' and item['status'] == 'NOT SAFE' for item in infrastructure)
        has_paths = len(attack_paths) > 0

        attack_possible = has_public_ec2 and has_admin_iam and has_paths
        
        if not attack_possible:
            return {
                "attack_possible": False,
                "risk_level": "LOW",
                "estimated_instances": 0,
                "monthly_attack_cost": 0,
                "reasons": ["Infrastructure follows secure configuration."]
            }

        # Determine Risk Level based on number of paths and risky resources
        risk_level = "HIGH"
        instances = 50
        cost = 400 # Default high impact

        num_risky = len([i for i in infrastructure if i['status'] == 'NOT SAFE'])
        
        if num_risky <= 2:
            risk_level = "LOW"
            instances = 2
            cost = 16
        elif num_risky <= 5:
            risk_level = "MEDIUM"
            instances = 10
            cost = 80
        else:
            risk_level = "HIGH"
            instances = 50
            cost = 400

        return {
            "attack_possible": True,
            "risk_level": risk_level,
            "estimated_instances": instances,
            "monthly_attack_cost": cost,
            "reasons": [
                "Publicly exposed EC2 detected as entry point",
                "Administrative IAM role allows unauthorized resource creation",
                f"Valid attack path confirmed through {len(attack_paths)} vector(s)"
            ]
        }

    @staticmethod
    def generate_cost_spike_series(base_cost, attack_cost):
        """
        Generates a 10-day cost spike timeline.
        """
        daily_base = base_cost / 30
        daily_attack_max = attack_cost / 30
        
        series = []
        days = [1, 2, 3, 5, 7, 10]
        
        for day in days:
            # Exponential growth simulation of the attack
            # Day 1: just base
            # Day 10: base + full attack cost
            growth_factor = (day / 10) ** 2 # Quadratic growth
            current_day_cost = daily_base + (daily_attack_max * growth_factor * day)
            
            series.append({
                "day": day,
                "cost": round(current_day_cost, 2)
            })
            
        return series
