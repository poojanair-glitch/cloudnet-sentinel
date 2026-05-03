import argparse
import boto3
import json
import os
from scanner.ec2_scanner import scan_ec2
from scanner.iam_scanner import scan_iam
from scanner.s3_scanner import scan_s3
from engine.graph_engine import GraphEngine
from engine.attack_path_engine import AttackPathEngine
from engine.risk_engine import RiskEngine
from engine.cost_engine import CostEngine
from engine.fix_engine import FixEngine

def main():
    parser = argparse.ArgumentParser(description="CloudNet Sentinel CLI")
    parser.add_argument("--access-key", help="AWS Access Key")
    parser.add_argument("--secret-key", help="AWS Secret Key")
    parser.add_argument("--region", default="us-east-1", help="AWS Region")
    args = parser.parse_args()

    # Use environment variables if CLI args are missing
    access_key = args.access_key or os.getenv("AWS_ACCESS_KEY_ID")
    secret_key = args.secret_key or os.getenv("AWS_SECRET_ACCESS_KEY")
    region = args.region

    if not access_key or not secret_key:
        print("Error: AWS Credentials required.")
        return

    print("--- CloudNet Sentinel Scan ---")
    
    session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region
    )

    print("Scanning EC2...")
    ec2_data = scan_ec2(session)
    print("Scanning IAM...")
    iam_data = scan_iam(session)
    print("Scanning S3...")
    s3_data = scan_s3(session)

    scan_results = {
        "ec2": ec2_data,
        "iam": iam_data,
        "s3": s3_data
    }

    print("Building graph...")
    ge = GraphEngine()
    graph = ge.build_graph(scan_results)

    print("Detecting attack paths...")
    ape = AttackPathEngine(graph)
    paths = ape.find_attack_paths()

    print(f"\nFound {len(paths)} Multi-step Attack Paths:")
    for p_info in paths:
        path = p_info['path']
        risk = RiskEngine.calculate_risk(path, graph)
        cost = CostEngine.calculate_impact(path, graph)
        
        print(f"\nPath: {' -> '.join(path)}")
        print(f"Risk Score: {risk['score']} ({risk['severity']})")
        print(f"Cost Impact: ₹{cost['total_cost']}")
        print("Reasons:")
        for r in p_info['reasons']:
            print(f" - {r}")
            
    print("\nScan Complete.")

if __name__ == "__main__":
    main()
