import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("../performance.csv")

# Metrics
avg = df['duration_micro'].mean()
p95 = df['duration_micro'].quantile(0.95)
_min = df['duration_micro'].min()
_max = df['duration_micro'].max()

print(f"Average: {avg:.2f} µs")
print(f"Min:     {_min:.2f} µs")
print(f"Max:     {_max:.2f} µs")
print(f"95th %:  {p95:.2f} µs")

# Plotting
plt.figure(figsize=(10, 6))
plt.plot(df['packet_index'], df['duration_micro'], label="Processing time per packet")
plt.axhline(avg, color='red', linestyle='--', label='Average')
plt.axhline(p95, color='orange', linestyle='--', label='95th percentile')
plt.xlabel("Packet ID")
plt.ylabel("Processing Time (µs)")
plt.title("Per-Packet Processing Time")
plt.legend()
plt.tight_layout()
plt.savefig("blocklist_performance.png")
plt.show()
