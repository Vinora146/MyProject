import requests
import zipfile
import os
from oletools.olevba import VBA_Parser
import time

# Your VirusTotal API Key
VT_API_KEY = "8d4b2c32b8d0a08dead756b0ee616a8782ace3b25429ebd7068c1c2d34dea5a6"  # Replace this with your actual API key  

# Function to send file to VirusTotal for scanning
def scan_with_virustotal(file_path):
    """Send the file to VirusTotal for scanning."""
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VT_API_KEY}
    
    with open(file_path, "rb") as file:
        files = {"file": file}
        response = requests.post(url, headers=headers, files=files)

    if response.status_code == 200:
        return response.json()  # Return JSON response containing the scan report
    else:
        print(f"❌ Error: {response.status_code}")
        return None

# Function to process VirusTotal's response and check for malicious detections
def process_virustotal_response(response):
    """Process VirusTotal API response to check for malicious detections."""
    if response and response.get("data"):
        data = response["data"]
        attributes = data.get("attributes", {})
        scan_results = attributes.get("last_analysis_results", {})

        # Check if any antivirus engine flagged the file as malicious
        malicious_engines = []
        for engine, result in scan_results.items():
            if result["category"] == "malicious":
                malicious_engines.append(engine)

        if malicious_engines:
            print(f"🚨 Malicious file detected by VirusTotal:")
            for engine in malicious_engines:
                print(f"    - Detected by {engine}")
            return True  # Flagged as malicious
        else:
            return False  # No malicious detections
    else:
        print("❌ Error: VirusTotal response is missing data.")
        return False

# Function to extract VBA macros from OLE-based Office files
def extract_vba_from_ole(file_path):
    """ Extract VBA macros from OLE-based Office documents (old .doc, .xls, .ppt, .docm, etc.) """
    try:
        vba_parser = VBA_Parser(file_path)
        if vba_parser.detect_vba_macros():
            vba_code = []
            for (_, _, _, vba_code_chunk) in vba_parser.extract_macros():
                vba_code.append(vba_code_chunk)
            return "\n".join(vba_code) if vba_code else None
    except Exception as e:
        print(f"❌ Error extracting VBA from {file_path}: {e}")
    return None

# Function to extract VBA macros from OpenXML-based Office files (.docx, .xlsx, .pptx)
def extract_vba_from_openxml(file_path):
    """Extract VBA macros from OpenXML Office files (.docx, .xlsx, .pptx)."""
    try:
        with zipfile.ZipFile(file_path, 'r') as zip_file:
            # Search for the vbaProject.bin file within the zip archive
            for name in zip_file.namelist():
                if "vbaProject.bin" in name:
                    with zip_file.open(name) as vba_file:
                        # Read and return the VBA content (we'll decode it for better readability)
                        vba_code = vba_file.read().decode(errors="ignore")
                        return vba_code
    except Exception as e:
        print(f"❌ Error extracting VBA from OpenXML file {file_path}: {e}")
    return None

# Function to detect malicious VBA patterns in the code
def detect_malicious_vba(vba_code):
    """Detect common malicious patterns in VBA code."""
    malicious_patterns = [
        ("Execution Attack", "Shell"),
        ("Execution Attack", "CreateObject"),
        ("Execution Attack", "WScript.Shell"),
        ("Auto-execution Macros Attack", "AutoOpen"),
        ("Auto-execution Macros Attack", "Auto_Close"),
        ("Auto-execution Macros Attack", "Workbook_Open"),
        ("Auto-execution Macros Attack", "Document_Open")
    ]

    detected_threats = []

    # Check for each pattern in the VBA code
    for category, keyword in malicious_patterns:
        if keyword.lower() in vba_code.lower():
            detected_threats.append((category, keyword))

    return detected_threats

# Function to scan a single file for malicious VBA macros and cloud-based signature scanning
def scan_file(file_path):
    """ Scan a single file for malicious VBA macros. """
    print(f"🔍 Scanning: {file_path}")
    
    # First, scan the file with VirusTotal for signature-based detection
    vt_response = scan_with_virustotal(file_path)
    if vt_response:
        is_malicious = process_virustotal_response(vt_response)
        if is_malicious:
            print(f"🚨 Malicious file detected by VirusTotal: {file_path}")
        else:
            print("✅ File is clean according to VirusTotal.\n")

    # Check file extension to decide extraction method
    if file_path.endswith((".docm", ".xlsm", ".pptm", ".doc", ".xls", ".ppt")):
        vba_code = extract_vba_from_ole(file_path)
    elif file_path.endswith((".docx", ".xlsx", ".pptx")):
        vba_code = extract_vba_from_openxml(file_path)
    else:
        print("⚠️ Unsupported file type. Skipping...\n")
        return

    if vba_code:
        print("🔍 Scanning VBA code for malicious patterns...")
        # You can integrate your existing detection logic here for static code scanning
        threats = detect_malicious_vba(vba_code)
        if threats:
            print(f"🚨 Malicious VBA macros detected in {file_path}")
            for category, keyword in threats:
                print(f"⚠️ Detected {category} Attack: {keyword}")
        else:
            print("✅ Clean VBA macros found.\n")
    else:
        print("✅ No VBA macros detected.\n")

# Function to scan all Office documents in a folder
def scan_folder(folder_path):
    """ Scan all Office documents in a folder. """
    print(f"\n📂 Scanning folder: {folder_path}\n")
    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        if file_path.endswith((".docm", ".xlsm", ".pptm", ".doc", ".xls", ".ppt", ".docx", ".xlsx", ".pptx")):
            scan_file(file_path)

# Function to decide whether the given path is a file or a folder and scan accordingly
def scan_path(path):
    """ Decide whether the given path is a file or a folder and scan accordingly. """
    if os.path.isdir(path):
        scan_folder(path)
    elif os.path.isfile(path):
        scan_file(path)
    else:
        print("❌ Invalid path! Please provide a valid file or folder.")

# Main block to run the script
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Scan Office documents for malicious VBA macros.")
    parser.add_argument("path", help="File or folder to scan")
    args = parser.parse_args()
    
    scan_path(args.path)
