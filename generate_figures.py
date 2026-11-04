import matplotlib.pyplot as plt
import numpy as np

# ==========================================
# GENERATE FIGURE 4: Explanation Fidelity
# ==========================================
labels = ['Unconstrained\nBaseline', 'Constrained\n(Insufficient)', 'Constrained\n(Sufficient)']
confidence_scores = [0.8, 0.2, 0.85]
colors = ['#d62728', '#ff7f0e', '#2ca02c'] # Red, Orange, Green

plt.figure(figsize=(8, 5))
bars = plt.bar(labels, confidence_scores, color=colors, edgecolor='black', alpha=0.8)

# Add value labels on top of bars
for bar in bars:
    yval = bar.get_height()
    plt.text(bar.get_x() + bar.get_width()/2, yval + 0.02, f'{yval:.2f}', 
             ha='center', va='bottom', fontweight='bold')

plt.axhline(y=0.7, color='red', linestyle='--', label='Policy Gate Threshold (0.7)')
plt.ylim(0, 1.0)
plt.ylabel('LLM Confidence Score', fontweight='bold')
plt.title('Figure 4: Layer 1 Explanation Fidelity Across Three Conditions', fontweight='bold', pad=15)
plt.legend(loc='upper right')
plt.grid(axis='y', linestyle='--', alpha=0.7)
plt.tight_layout()

# Save as high-res 300 DPI image
plt.savefig('Figure4_Explanation_Fidelity.png', dpi=300)
plt.show()


# ==========================================
# GENERATE FIGURE 5: VirusTotal Detections
# ==========================================
# Data from your CSV
iocs = ['15.204.59.70', '162.35.99.94', 'malicious.example', 'deadbeef...']
malicious = [11, 6, 0, 0] # Invalid IOCs returned 0 data
suspicious = [2, 4, 0, 0]

x = np.arange(len(iocs))
width = 0.35

fig, ax = plt.subplots(figsize=(10, 5))
rects1 = ax.bar(x - width/2, malicious, width, label='Malicious', color='#d62728')
rects2 = ax.bar(x + width/2, suspicious, width, label='Suspicious', color='#ff7f0e')

# Add text for labels, title and custom x-axis tick labels, etc.
ax.set_ylabel('Detection Counts', fontweight='bold')
ax.set_title('Figure 5: VirusTotal Detections per IOC', fontweight='bold', pad=15)
ax.set_xticks(x)
ax.set_xticklabels(iocs)
ax.legend()

# Add labels to the bars
ax.bar_label(rects1, padding=3)
ax.bar_label(rects2, padding=3)

plt.grid(axis='y', linestyle='--', alpha=0.7)
fig.tight_layout()

# Save as high-res 300 DPI image
plt.savefig('Figure5_VirusTotal_Detections.png', dpi=300)
plt.show()