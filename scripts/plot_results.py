#!/usr/bin/env python3
"""
SRA Attack Results Plotting

Creates visualizations of attack evaluation results including
degradation curves, latency analysis, and leakage scoring.
"""

import json
import matplotlib.pyplot as plt
import numpy as np
import os
from pathlib import Path
import sys

def load_results():
    """Load evaluation results from JSON files."""
    summary_path = "results/runs/summary.json"
    detailed_path = "results/runs/detailed.json"
    
    if not os.path.exists(summary_path):
        print(f"Results file not found: {summary_path}")
        print("Run the evaluation first: python -m scripts.run_adaptive_eval")
        return None, None
    
    with open(summary_path, 'r') as f:
        summary = json.load(f)
    
    detailed = []
    if os.path.exists(detailed_path):
        with open(detailed_path, 'r') as f:
            detailed = json.load(f)
    
    return summary, detailed

def plot_attack_degradation(summary, detailed):
    """Plot attack success rate over time/attempts."""
    if not detailed:
        print("No detailed results available for degradation plot")
        return
    
    # Group results by attack index
    attack_groups = {}
    for result in detailed:
        attack_idx = result.get("attack_idx", 0)
        if attack_idx not in attack_groups:
            attack_groups[attack_idx] = []
        attack_groups[attack_idx].append(result)
    
    plt.figure(figsize=(12, 8))
    
    # Plot 1: Overall success rate by attempt number
    plt.subplot(2, 2, 1)
    attempt_numbers = [r.get("attempt_idx", 0) for r in detailed]
    success_by_attempt = {}
    
    for result in detailed:
        attempt_idx = result.get("attempt_idx", 0)
        is_success = result.get("status") == "allowed"
        
        if attempt_idx not in success_by_attempt:
            success_by_attempt[attempt_idx] = []
        success_by_attempt[attempt_idx].append(is_success)
    
    attempt_indices = sorted(success_by_attempt.keys())
    success_rates = [np.mean(success_by_attempt[idx]) for idx in attempt_indices]
    
    plt.plot(attempt_indices, success_rates, 'b-o', markersize=4)
    plt.xlabel('Attempt Number')
    plt.ylabel('Attack Success Rate')
    plt.title('Attack Success by Attempt Number')
    plt.grid(True, alpha=0.3)
    plt.ylim(0, 1)
    
    # Plot 2: Leakage scores over time
    plt.subplot(2, 2, 2)
    leakage_scores = [r.get("leakage_score", 0) for r in detailed]
    plt.plot(range(len(leakage_scores)), leakage_scores, 'r-', alpha=0.7)
    plt.xlabel('Attempt Index')
    plt.ylabel('Leakage Score')
    plt.title('Information Leakage Over Attempts')
    plt.grid(True, alpha=0.3)
    plt.ylim(0, 1)
    
    # Plot 3: Status distribution
    plt.subplot(2, 2, 3)
    statuses = [r.get("status", "unknown") for r in detailed]
    status_counts = {}
    for status in statuses:
        status_counts[status] = status_counts.get(status, 0) + 1
    
    if status_counts:
        labels = list(status_counts.keys())
        sizes = list(status_counts.values())
        colors = ['red' if 'block' in l else 'green' if 'allow' in l else 'orange' for l in labels]
        
        plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
        plt.title('Response Status Distribution')
    
    # Plot 4: Latency analysis
    plt.subplot(2, 2, 4)
    latencies = [r.get("latency_ms", 0) for r in detailed]
    if latencies:
        plt.hist(latencies, bins=20, alpha=0.7, color='purple', edgecolor='black')
        plt.xlabel('Latency (ms)')
        plt.ylabel('Frequency')
        plt.title('Response Latency Distribution')
        plt.grid(True, alpha=0.3)
        
        # Add statistics
        mean_lat = np.mean(latencies)
        plt.axvline(mean_lat, color='red', linestyle='--', label=f'Mean: {mean_lat:.1f}ms')
        plt.legend()
    
    plt.tight_layout()
    return plt

def plot_mutation_effectiveness(detailed):
    """Plot effectiveness of different mutation strategies."""
    if not detailed:
        return
    
    # Group by mutation type
    mutation_stats = {}
    for result in detailed:
        mutation = result.get("mutation_kind", "unknown")
        status = result.get("status", "unknown")
        leakage = result.get("leakage_score", 0)
        
        if mutation not in mutation_stats:
            mutation_stats[mutation] = {
                "total": 0,
                "blocked": 0,
                "allowed": 0,
                "leakage_scores": []
            }
        
        mutation_stats[mutation]["total"] += 1
        mutation_stats[mutation]["leakage_scores"].append(leakage)
        
        if status == "blocked":
            mutation_stats[mutation]["blocked"] += 1
        elif status == "allowed":
            mutation_stats[mutation]["allowed"] += 1
    
    if not mutation_stats:
        return
    
    plt.figure(figsize=(14, 6))
    
    # Plot 1: Success rate by mutation type
    plt.subplot(1, 2, 1)
    mutations = list(mutation_stats.keys())
    success_rates = []
    
    for mutation in mutations:
        stats = mutation_stats[mutation]
        success_rate = stats["allowed"] / max(stats["total"], 1)
        success_rates.append(success_rate)
    
    bars = plt.bar(range(len(mutations)), success_rates, 
                   color=['red' if sr > 0.5 else 'orange' if sr > 0.2 else 'green' for sr in success_rates])
    plt.xlabel('Mutation Type')
    plt.ylabel('Success Rate')
    plt.title('Attack Success Rate by Mutation Type')
    plt.xticks(range(len(mutations)), mutations, rotation=45, ha='right')
    plt.ylim(0, 1)
    plt.grid(True, alpha=0.3)
    
    # Add value labels on bars
    for i, (bar, rate) in enumerate(zip(bars, success_rates)):
        plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                f'{rate:.2f}', ha='center', va='bottom', fontsize=9)
    
    # Plot 2: Average leakage by mutation type
    plt.subplot(1, 2, 2)
    avg_leakages = []
    
    for mutation in mutations:
        stats = mutation_stats[mutation]
        avg_leakage = np.mean(stats["leakage_scores"]) if stats["leakage_scores"] else 0
        avg_leakages.append(avg_leakage)
    
    bars2 = plt.bar(range(len(mutations)), avg_leakages,
                    color=['darkred' if al > 0.5 else 'orange' if al > 0.2 else 'darkgreen' for al in avg_leakages])
    plt.xlabel('Mutation Type')
    plt.ylabel('Average Leakage Score')
    plt.title('Average Information Leakage by Mutation Type')
    plt.xticks(range(len(mutations)), mutations, rotation=45, ha='right')
    plt.ylim(0, 1)
    plt.grid(True, alpha=0.3)
    
    # Add value labels
    for i, (bar, leakage) in enumerate(zip(bars2, avg_leakages)):
        plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                f'{leakage:.3f}', ha='center', va='bottom', fontsize=9)
    
    plt.tight_layout()
    return plt

def create_summary_report(summary, detailed):
    """Create a text summary report."""
    if not summary:
        return "No summary data available"
    
    config = summary.get("evaluation_config", {})
    results = summary.get("results", {})
    
    report = f"""
SRA Attack Evaluation Summary Report
=====================================

Configuration:
- Strategy: {config.get('strategy', 'unknown')}
- Mutation Budget: {config.get('budget', {}).get('mutations', 'unknown')}
- Base Attacks: {config.get('num_base_attacks', 'unknown')}
- Mutators: {config.get('num_mutators', 'unknown')}

Results:
- Attacks Completed: {results.get('attacks_completed', 0)}
- Total Attempts: {results.get('total_attempts', 0)}
- Blocked Attempts: {results.get('blocked_attempts', 0)}
- Allowed Attempts: {results.get('allowed_attempts', 0)}
- Template Responses: {results.get('template_attempts', 0)}

Security Metrics:
- Block Rate: {results.get('block_rate', 0):.1%}
- Allow Rate (Attack Success): {results.get('allow_rate', 0):.1%}
- Average Latency: {results.get('avg_latency_ms', 0):.1f}ms
- Average Leakage Score: {results.get('avg_leakage_score', 0):.3f}

Assessment:
"""
    
    block_rate = results.get('block_rate', 0)
    if block_rate > 0.9:
        report += "✓ Excellent: Very high block rate indicates strong security\n"
    elif block_rate > 0.7:
        report += "⚠ Good: High block rate with some room for improvement\n"
    else:
        report += "❌ Concerning: Low block rate indicates security vulnerabilities\n"
    
    avg_latency = results.get('avg_latency_ms', 0)
    if avg_latency < 50:
        report += "✓ Excellent: Low latency maintains good user experience\n"
    elif avg_latency < 100:
        report += "⚠ Acceptable: Moderate latency impact\n"
    else:
        report += "❌ Concerning: High latency may impact usability\n"
    
    return report

def main():
    """Generate all plots and reports."""
    print("Loading evaluation results...")
    summary, detailed = load_results()
    
    if not summary:
        return 1
    
    print(f"Loaded results: {summary['results']['total_attempts']} total attempts")
    
    # Create output directory
    os.makedirs("results/plots", exist_ok=True)
    
    # Generate main degradation plot
    print("Creating degradation analysis plot...")
    plt1 = plot_attack_degradation(summary, detailed)
    if plt1:
        plt1.savefig("results/plots/degradation_curve.png", dpi=300, bbox_inches='tight')
        print("✓ Saved: results/plots/degradation_curve.png")
        plt1.close()
    
    # Generate mutation effectiveness plot
    print("Creating mutation effectiveness plot...")
    plt2 = plot_mutation_effectiveness(detailed)
    if plt2:
        plt2.savefig("results/plots/mutation_effectiveness.png", dpi=300, bbox_inches='tight')
        print("✓ Saved: results/plots/mutation_effectiveness.png")
        plt2.close()
    
    # Generate summary report
    print("Creating summary report...")
    report = create_summary_report(summary, detailed)
    with open("results/plots/summary_report.txt", "w") as f:
        f.write(report)
    print("✓ Saved: results/plots/summary_report.txt")
    
    # Print summary to console
    print("\n" + "="*60)
    print(report)
    
    print("\nAll plots and reports generated successfully!")
    print("View results in: results/plots/")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())