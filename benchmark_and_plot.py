import subprocess
import re
import csv
import sys

def run_experiment(num_messages, num_issuers):
    cmd = ['./main_multi_issuer']
    input_str = f"{num_messages}\n{num_issuers}\n"
    
    result = subprocess.run(cmd, input=input_str, text=True, capture_output=True)
    output = result.stdout
    
    times = {
        'num_messages': num_messages,
        'verifySignature': 0.0,
        'verifyRandomizedCredential': 0.0,
        'generatePresentationPayload': 0.0,
        'verifyORProof': 0.0,
        'simulatePresentationPayloadByVerifier': 0.0
    }
    
    counts = {k: 0 for k in times.keys() if k != 'num_messages'}
    
    for line in output.split('\n'):
        if line.startswith('[Time]'):
            match = re.search(r'\[Time\]\s+(\w+)\s+execution time:\s+([0-9.]+)\s+ms', line)
            if match:
                func_name = match.group(1)
                time_val = float(match.group(2))
                if func_name in times:
                    times[func_name] += time_val
                    counts[func_name] += 1
                    
    for k, count in counts.items():
        if count > 0:
            times[k] /= count
            
    return times

def print_ascii_bar_chart(results, func_name):
    print(f"\n--- {func_name} (ms) ---")
    max_val = max([r[func_name] for r in results])
    if max_val == 0: max_val = 1
    
    for r in results:
        val = r[func_name]
        bar_len = int((val / max_val) * 40)
        bar = "█" * bar_len
        print(f"Attr={r['num_messages']:<2} | {bar} {val:.2f} ms")

def main():
    messages_list = [2, 4, 6, 8, 10, 12]
    issuers = 3
    results = []
    
    print("===========================================")
    print(f"Running benchmarks (Issuers = 1+1+{issuers})...")
    print("===========================================")
    
    for m in messages_list:
        print(f" -> Testing with num_messages = {m} ... ", end="")
        sys.stdout.flush()
        res = run_experiment(m, issuers)
        results.append(res)
        print("Done")
        
    csv_filename = 'performance_data.csv'
    with open(csv_filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        for r in results:
            writer.writerow(r)
    print(f"\nData saved to {csv_filename}")
    
    funcs_to_plot = [
        'verifySignature',
        'verifyRandomizedCredential',
        'generatePresentationPayload',
        'verifyORProof'
    ]
    
    for func in funcs_to_plot:
        print_ascii_bar_chart(results, func)

if __name__ == "__main__":
    main()
