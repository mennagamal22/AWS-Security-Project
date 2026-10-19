import json
import os

def classify_event(event):
    """
    Classify incoming CloudTrail events and detect security risks.
    """
    event_name = event.get("event_name", "")
    request_params = event.get("request_parameters", {})
    
    # Default state is benign
    change_type = "BENIGN"
    severity = "LOW"
    reason = "Normal activity or no major security risk detected."

    # 1. Security Group Rule: Open administrative ports (e.g., SSH=22, RDP=3389)
    if event_name in ["AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"]:
        items = request_params.get("ipPermissions", {}).get("items", [])
        for item in items:
            from_port = item.get("fromPort", 0)
            to_port = item.get("toPort", 0)
            ip_ranges = item.get("ipRanges", [])
            
            for ip_range in ip_ranges:
                cidr = ip_range.get("cidrIp", "")
                if cidr == "0.0.0.0/0" and (from_port <= 22 <= to_port or from_port <= 3389 <= to_port):
                    change_type = "SG_ADMIN_PORT_OPEN"
                    severity = "HIGH"
                    reason = f"Security group allows public access (0.0.0.0/0) on administrative port {from_port}."

    # 2. IAM Policy Rule: Admin privileges assignment
    elif event_name in ["AttachRolePolicy", "PutRolePolicy", "AttachUserPolicy"]:
        policy_arn = request_params.get("policyArn", "")
        policy_document = str(request_params.get("policyDocument", ""))
        
        if "AdministratorAccess" in policy_arn or '"Effect": "Allow", "Action": "*"' in policy_document:
            change_type = "IAM_ADMIN_PRIVILEGES_GRANTED"
            severity = "CRITICAL"
            reason = "Administrator access or full permissions granted to identity."

    # 3. S3 Bucket Rule: Public access granted
    elif event_name in ["DeletePublicAccessBlock", "PutBucketAcl"]:
        acl = request_params.get("AccessControlPolicy", {})
        if event_name == "DeletePublicAccessBlock" or "AllUsers" in str(acl):
            change_type = "S3_BUCKET_PUBLIC_ACCESS"
            severity = "HIGH"
            reason = "S3 Bucket public access block removed or bucket set to public."

    # Update event dictionary with classification results
    event["change_type"] = change_type
    event["severity"] = severity
    event["reason"] = reason
    return event

if __name__ == "__main__":
    # Get current script directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Path 1: Look inside src/detection
    file_path = os.path.join(current_dir, "sample_events.json")
    
    # Path 2: Fallback to root directory if not found in detection
    if not os.path.exists(file_path):
        root_dir = os.path.abspath(os.path.join(current_dir, "../../"))
        file_path = os.path.join(root_dir, "sample_events.json")

    # Test the classifier locally using the mock data file
    with open(file_path, "r") as f:
        events = json.load(f)
        
    for ev in events:
        result = classify_event(ev)
        print(json.dumps(result, indent=4, ensure_ascii=False))