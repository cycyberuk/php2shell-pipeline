import matplotlib.pyplot as plt
import numpy as np

# Data from your d3_results.json
labels = ['Verified IPs', 'Verified Domains']
malicious = [13, 13]
benign = [2, 2] # 15 total - 13 malicious = 2 benign

x = np.arange(len(labels))
width = 0.35

fig, ax = plt.subplots(figsize=(8, 5))
rects1 = ax.bar(x - width/2, malicious, width, label='Confirmed Malicious', color='#d62728')
rects2 = ax.bar(x + width/2, benign, width, label='Benign / Undetected', color='#2ca02c')

ax.set_ylabel('IOC Count', fontweight='bold')
ax.set_title('Figure 5: D3 Precision Analysis (Public PHP2Shell Dataset)', fontweight='bold', pad=15)
ax.set_xticks(x)
ax.set_xticklabels(labels)
ax.set_ylim(0, 16)
ax.legend()

ax.bar_label(rects1, padding=3)
ax.bar_label(rects2, padding=3)

plt.grid(axis='y', linestyle='--', alpha=0.7)
fig.tight_layout()

plt.savefig('Figure5_D3_Precision.png', dpi=300, bbox_inches='tight')
print("Saved: Figure5_D3_Precision.png")
plt.close()