import re
import csv
from collections import defaultdict, Counter

FAILED_LOGIN_THRESHOLD = 10

LOG_FILE = "sample.log"
OUTPUT_FILE = "log_analysis_results.csv"

def parse_log_file(file_path):
    with open(file_path, "r") as file:
        lines = file.readlines()
    return lines

def count_requests_per_ip(log_lines):
    ip_requests = defaultdict(int)
    for line in log_lines:
        ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
        if ip_match:
            ip_requests[ip_match.group(1)] += 1
    return sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)

def find_most_accessed_endpoint(log_lines):
    endpoints = Counter()
    for line in log_lines:
        endpoint_match = re.search(r'\"(?:GET|POST|PUT|DELETE) (\S+)', line)
        if endpoint_match:
            endpoints[endpoint_match.group(1)] += 1
    most_accessed = endpoints.most_common(1)[0]
    return most_accessed

def detect_suspicious_activity(log_lines):
    failed_logins = defaultdict(int)
    for line in log_lines:
        if '401' in line or 'Invalid credentials' in line:
            ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                failed_logins[ip_match.group(1)] += 1
    return {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}

def write_results_to_csv(ip_requests, most_accessed_endpoint, suspicious_ips, output_file):
    with open(output_file, "w", newline="") as file:
        writer = csv.writer(file)

        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_requests)

        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

def main():
    log_lines = parse_log_file(LOG_FILE)

    ip_requests = count_requests_per_ip(log_lines)
    most_accessed_endpoint = find_most_accessed_endpoint(log_lines)
    suspicious_ips = detect_suspicious_activity(log_lines)

    print("Requests per IP:")
    for ip, count in ip_requests:
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20} {count} failed login attempts")

    write_results_to_csv(ip_requests, most_accessed_endpoint, suspicious_ips, OUTPUT_FILE)
    print(f"\nResults saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()