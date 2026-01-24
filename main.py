from firewall.engine import FirewallEngine
import random

def fake_traffic():
    # Generate sample packets/events
    samples = [
        {"src_ip": "10.0.0.5", "dst_ip": "192.168.1.10", "src_port": 51515, "dst_port": 22, "protocol": "TCP", "direction": "IN"},
        {"src_ip": "192.168.1.11", "dst_ip": "8.8.8.8", "src_port": 54000, "dst_port": 53, "protocol": "UDP", "direction": "OUT"},
        {"src_ip": "203.0.113.10", "dst_ip": "192.168.1.10", "src_port": 44444, "dst_port": 80, "protocol": "TCP", "direction": "IN"},
        {"src_ip": "192.168.1.15", "dst_ip": "192.168.1.20", "src_port": 5000, "dst_port": 5001, "protocol": "TCP", "direction": "OUT"},
    ]
    while True:
        yield random.choice(samples)

def main():
    rules = FirewallEngine.load_rules("rules.json")
    fw = FirewallEngine(rules=rules, default_policy="DENY")

    traffic = fake_traffic()
    for i in range(10):
        packet = next(traffic)
        decision = fw.decide(packet)
        print(f"[{i+1}] {decision['decision']:<5} rule={decision['matched_rule']} packet={packet}")

    print("\nLog saved to firewall.log (JSON lines).")

if __name__ == "__main__":
    main()
