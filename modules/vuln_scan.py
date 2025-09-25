import subprocess
import os

def scan_vulnerabilities(domain):
    output_file = f"nuclei_{domain}.txt"
    try:
        command = ["nuclei", "-u", domain, "-o", output_file]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if not os.path.exists(output_file):
            return {"error": f"Nuclei failed: {result.stderr.decode().strip()}"}

        with open(output_file, 'r') as f:
            lines = f.readlines()
        return [line.strip() for line in lines] if lines else ["No CVEs found."]
    except Exception as e:
        return {"error": str(e)}
