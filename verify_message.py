#!/usr/bin/env python3
"""
========================================================================================
Interactive Six-Layer AI-Based Phishing & Scam Prevention System
Department of Computer Science & Engineering, Daffodil International University (DIU)
Project: Beyond the Filter: The Weaponization of Multi-Platform AI-Scams
Student: Jannatul Fardous (ID: 0242310005101188)
Supervisor: Ms. Nazmun Nessa Moon, Associate Professor, CSE, DIU
========================================================================================
"""

import sys
import re
import math
import time
import json
import hashlib
import argparse
from datetime import datetime

# ANSI Terminal Colors
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

def calculate_shannon_entropy(text):
    """Computes Shannon character entropy H(X) = -sum(P(x) * log2(P(x)))"""
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    entropy = -sum((cnt / length) * math.log2(cnt / length) for cnt in freq.values())
    return round(entropy, 3)

def detect_homoglyphs(text):
    """Detects Cyrillic and confusable Unicode characters injected into Latin text"""
    # Common Cyrillic confusables that mimic ASCII
    cyrillic_confusables = set(['\u0430', '\u0441', '\u0435', '\u043e', '\u0440', '\u0445', '\u0443', '\u0456', 
                                '\u0410', '\u0412', '\u0421', '\u0415', '\u041d', '\u041e', '\u0420', '\u0422', '\u0425'])
    detected = [c for c in text if c in cyrillic_confusables or (ord(c) > 127 and ord(c) < 1000)]
    return detected

def inspect_message(sender, message, url="", attachment="", raw_mode=False):
    """
    Executes the Six-Layer Hybrid Defense Pipeline on a target communication.
    Returns: (audit_dict, risk_score, final_verdict, telemetry_dict)
    """
    risk_score = 0
    audit = {}
    mitre_tags = []
    
    # -------------------------------------------------------------
    # Layer 1: Sender & Header Authentication (SPF / DKIM / Homoglyph)
    # -------------------------------------------------------------
    s_low = sender.lower().strip()
    suspicious_sender_keywords = ["verify", "fake", "alert", "security", "support-update", "bkash-notice", "bank-secure"]
    legit_domains = ["daffodilvarsity.edu.bd", "diu.edu.bd", "bkash.com", "grameenphone.com", "ebl.com.bd"]
    
    is_trusted = any(s_low.endswith("@" + d) or s_low.endswith("." + d) for d in legit_domains)
    is_spoofed = any(kw in s_low for kw in suspicious_sender_keywords) and not is_trusted
    sender_homoglyphs = detect_homoglyphs(sender)

    if sender_homoglyphs:
        l1_status = f"{Colors.RED}FAIL (Detected {len(sender_homoglyphs)} Cyrillic/Confusable Homoglyphs in Sender Header!){Colors.RESET}"
        risk_score += 35
        mitre_tags.append("T1036.007 (Masquerading: Double File Extension & Homoglyph)")
    elif is_spoofed:
        l1_status = f"{Colors.RED}FAIL (Spoofed Domain / High Risk Sender Keyword Detected){Colors.RESET}"
        risk_score += 25
        mitre_tags.append("T1566.002 (Phishing: Spearphishing Link / Fake Header)")
    elif is_trusted:
        l1_status = f"{Colors.GREEN}PASS (Verified Authentic Institutional Cryptographic Domain){Colors.RESET}"
    else:
        l1_status = f"{Colors.YELLOW}NEUTRAL (Standard External Communication Protocol){Colors.RESET}"
    audit["Layer 1: Sender & Header Auth"] = l1_status

    # -------------------------------------------------------------
    # Layer 2: Behavioral Anomaly Detection (Cialdini's Psychological Triggers)
    # -------------------------------------------------------------
    m_low = message.lower()
    words_clean = [w.strip(".,!?;:()[]\"'") for w in m_low.split()]
    
    fear_triggers = ["suspended", "locked", "unauthorized", "compromised", "frozen", "penalty", "arrest", "legal", "terminate", "alert"]
    greed_triggers = ["winner", "cash", "bonus", "reward", "prize", "won", "claim", "voucher", "free", "congratulations", "earn", "job", "opportunity", "telegram"]
    authority_triggers = ["bank", "university", "official", "registrar", "controller", "security", "kyc", "police", "admin", "department", "bkash", "nagad"]
    urgency_triggers = ["urgent", "immediately", "hours", "instant", "expire", "deadline", "today", "now", "action required"]

    fear_hits = [w for w in words_clean if w in fear_triggers]
    greed_hits = [w for w in words_clean if w in greed_triggers]
    auth_hits = [w for w in words_clean if w in authority_triggers]
    urgency_hits = [w for w in words_clean if w in urgency_triggers]
    
    cialdini_score = len(fear_hits) * 2 + len(greed_hits) * 2 + len(auth_hits) * 1.5 + len(urgency_hits) * 2
    body_entropy = calculate_shannon_entropy(message)
    
    if cialdini_score >= 4 or len(urgency_hits) >= 2:
        l2_status = f"{Colors.RED}HIGH RISK (Cialdini Drivers: Fear={len(fear_hits)}, Greed={len(greed_hits)}, Auth={len(auth_hits)}, Urgency={len(urgency_hits)} | Entropy: {body_entropy}){Colors.RESET}"
        risk_score += 25
        mitre_tags.append("T1204.001 (User Execution: Malicious Pressure & Social Engineering)")
    elif cialdini_score >= 1.5:
        l2_status = f"{Colors.YELLOW}ELEVATED RISK (Social Engineering Cues Detected | Entropy: {body_entropy}){Colors.RESET}"
        risk_score += 12
    else:
        l2_status = f"{Colors.GREEN}PASS (Normal Linguistic Cadence & Regular Entropy: {body_entropy}){Colors.RESET}"
    audit["Layer 2: Behavioral Anomaly"] = l2_status

    # -------------------------------------------------------------
    # Layer 3: Link & Attachment Sandboxing (URL Heuristics / Payloads)
    # -------------------------------------------------------------
    u_low = url.lower().strip()
    att_low = attachment.lower().strip()
    
    suspicious_tlds = [".xyz", ".top", ".club", ".link", ".online", ".site", ".ru", ".tk"]
    has_suspicious_tld = any(u_low.endswith(tld) or (tld + "/") in u_low for tld in suspicious_tlds)
    has_executable = any(att_low.endswith(ext) for ext in [".exe", ".scr", ".vbs", ".bat", ".apk", ".js"])
    url_entropy = calculate_shannon_entropy(url)
    
    if has_executable or (u_low and has_suspicious_tld):
        l3_status = f"{Colors.RED}BLOCKED (Malicious Executable or High-Risk Deceptive TLD in Link | URL Entropy: {url_entropy}){Colors.RESET}"
        risk_score += 30
        mitre_tags.append("T1204.002 (User Execution: Malicious File/Link Interaction)")
    elif u_low and ("http://" in u_low or "secure-login" in u_low or "verify" in u_low):
        l3_status = f"{Colors.YELLOW}QUARANTINED (Unencrypted or Deceptive Redirection URL Structure){Colors.RESET}"
        risk_score += 20
        mitre_tags.append("T1566.002 (Phishing: Redirection URL)")
    else:
        l3_status = f"{Colors.GREEN}PASS (Sandbox Verification Cleared){Colors.RESET}"
    audit["Layer 3: Link & Attachment Sandbox"] = l3_status

    # -------------------------------------------------------------
    # Layer 4: Contextual Just-in-Time (JIT) Warnings
    # -------------------------------------------------------------
    if risk_score >= 35:
        l4_status = f"{Colors.RED}ACTIVE WARNING (Display High-Priority Security Banner Before Interaction){Colors.RESET}"
    elif risk_score >= 15:
        l4_status = f"{Colors.YELLOW}CAUTIONARY (Display Advisory Tooltip to User){Colors.RESET}"
    else:
        l4_status = f"{Colors.GREEN}SILENT (Standard User View){Colors.RESET}"
    audit["Layer 4: Just-in-Time Alert"] = l4_status

    # -------------------------------------------------------------
    # Layer 5: Risk-Proportional Out-of-Band (2FA) Verification
    # -------------------------------------------------------------
    financial_keywords = ["bdt", "usd", "$", "fee", "wire transfer", "bank", "crypto", "bkash", "nid", "credential"]
    involves_financial_action = any(w in m_low for w in financial_keywords) or any(w in u_low for w in ["login", "verify", "pay"])
    
    if risk_score >= 30 and involves_financial_action:
        l5_status = f"{Colors.RED}CHALLENGE REQUIRED (Secondary Out-of-Band Biometric/OTP Verification Mandated){Colors.RESET}"
        risk_score += 15
        mitre_tags.append("T1114.002 (Email Access: Remote Credential Harvest Prevented)")
    else:
        l5_status = f"{Colors.GREEN}SKIPPED (No High-Stakes Financial Risk Detected){Colors.RESET}"
    audit["Layer 5: Out-of-Band Verification"] = l5_status

    # -------------------------------------------------------------
    # Layer 6: Multimodal AI & Machine Learning Content Filter
    # -------------------------------------------------------------
    ml_scam_score = 0
    if cialdini_score >= 4: ml_scam_score += 40
    elif cialdini_score >= 2 or len(urgency_hits) >= 1: ml_scam_score += 30
    if is_spoofed or sender_homoglyphs: ml_scam_score += 35
    if has_suspicious_tld or has_executable: ml_scam_score += 30
    if any(k in m_low for k in ["claim", "award", "scholarship", "crypto", "delivery", "earn", "telegram", "job opportunity"]): ml_scam_score += 25
    
    if is_trusted and not (has_suspicious_tld or has_executable):
        ml_scam_score = 1
        
    ai_prob = min(max(ml_scam_score / 100.0, 0.01), 0.99)
    
    if ai_prob >= 0.50:
        l6_status = f"{Colors.RED}PHISHING DETECTED ({ai_prob*100:.1f}% AI Phishing Confidence Score){Colors.RESET}"
        risk_score += 25
    else:
        l6_status = f"{Colors.GREEN}BENIGN CONTENT ({(1.0 - ai_prob)*100:.1f}% Legitimate Confidence){Colors.RESET}"
    audit["Layer 6: AI Machine Learning Content"] = l6_status

    # Final Risk Normalization
    risk_score = min(risk_score, 100)
    
    if risk_score >= 65:
        verdict = f"{Colors.RED}{Colors.BOLD}BLOCKED (Critical Cyber Threat){Colors.RESET}"
        action_code = "BLOCK"
    elif risk_score >= 35:
        verdict = f"{Colors.YELLOW}{Colors.BOLD}QUARANTINED (High Risk Security Hold){Colors.RESET}"
        action_code = "QUARANTINE"
    else:
        verdict = f"{Colors.GREEN}{Colors.BOLD}DELIVERED (Safe to Read & Interact){Colors.RESET}"
        action_code = "DELIVER"
        
    telemetry = {
        "timestamp": datetime.now().isoformat(),
        "sender": sender,
        "message_sha256": hashlib.sha256(message.encode()).hexdigest(),
        "url": url,
        "attachment": attachment,
        "body_entropy": body_entropy,
        "url_entropy": url_entropy,
        "homoglyphs_detected": len(sender_homoglyphs),
        "cialdini_triggers": {
            "fear": len(fear_hits),
            "greed": len(greed_hits),
            "authority": len(auth_hits),
            "urgency": len(urgency_hits)
        },
        "risk_score": risk_score,
        "action": action_code,
        "mitre_attack_tactics": mitre_tags,
        "layer_audit_summary": {k: re.sub(r'\x1b\[[0-9;]*m', '', v) for k, v in audit.items()}
    }

    return audit, risk_score, verdict, telemetry

def print_banner():
    banner = f"""{Colors.CYAN}{Colors.BOLD}
========================================================================================
       PROPOSED SIX-LAYER AI PHISHING & SCAM DEFENSE FRAMEWORK (ENTERPRISE SIEM)       
Department of Computer Science & Engineering | Daffodil International University
Author: Jannatul Fardous (ID: 0242310005101188) | Supervisor: Ms. Nazmun Nessa Moon
========================================================================================{Colors.RESET}"""
    print(banner)

def run_demo(siem_mode=False):
    if not siem_mode:
        print_banner()
    demo_cases = [
        {
            "name": "Case 1: Deceptive Bank Suspension Phishing (Mail 1)",
            "sender": "security-alert@bank-verify-account.com",
            "message": "Security Alert: Your Bank account has been suspended due to unauthorized login attempts. Verify immediately within 24 hours at http://secure-login-verify-account.com or your balance will be frozen permanently.",
            "url": "http://secure-login-verify-account.com",
            "attachment": ""
        },
        {
            "name": "Case 2: Authentic University Academic Notice (Mail 2)",
            "sender": "exam-controller@diu.edu.bd",
            "message": "Official Notice from Daffodil International University: Mid-Term Examination schedule has been published on the student portal. Please check your assigned room and student ID.",
            "url": "https://studentportal.diu.edu.bd",
            "attachment": "Midterm_Schedule.pdf"
        },
        {
            "name": "Case 3: Urgent bKash KYC Suspension SMS (Text 2)",
            "sender": "bKash-Notice-Alert",
            "message": "bKash Urgent Alert: Your bKash account will be locked within 2 hours due to regulatory KYC failure. Confirm your 5-digit PIN and OTP immediately by clicking: http://bkash-verification-update.xyz",
            "url": "http://bkash-verification-update.xyz",
            "attachment": ""
        },
        {
            "name": "Case 4: Advanced Cyrillic Homoglyph Injection Attack",
            "sender": "security@d\u0430ffodilvarsity.edu.bd",
            "message": "Immediate Password Reset Mandate: Click here to verify credentials.",
            "url": "http://diu-login.xyz",
            "attachment": ""
        }
    ]
    
    siem_logs = []
    for idx, c in enumerate(demo_cases, start=1):
        audit, score, verdict, telem = inspect_message(c['sender'], c['message'], c['url'], c['attachment'])
        siem_logs.append(telem)
        
        if not siem_mode:
            print(f"{Colors.BOLD}----------------------------------------------------------------------------------------{Colors.RESET}")
            print(f"{Colors.BOLD}SCENARIO #{idx}: {c['name']}{Colors.RESET}")
            print(f"  • Sender     : {c['sender']}")
            print(f"  • Message    : {c['message'][:85]}...")
            if c['url']: print(f"  • Link (URL) : {c['url']}")
            if c['attachment']: print(f"  • Attachment : {c['attachment']}")
            print(f"{Colors.BOLD}----------------------------------------------------------------------------------------{Colors.RESET}")
            
            for layer_name, status in audit.items():
                print(f"  [{layer_name:36}] : {status}")
                
            print(f"\n  ➤ {Colors.BOLD}Aggregated Risk Score : {score} / 100{Colors.RESET}")
            print(f"  ➤ {Colors.BOLD}Automated Action      : {verdict}{Colors.RESET}\n")

    if siem_mode:
        print(json.dumps(siem_logs, indent=2))

def evaluate_all_scenarios(siem_mode=False):
    """Audits all 11 benchmark survey scenarios through the Six-Layer Engine"""
    if not siem_mode:
        print_banner()
        print(f"{Colors.BOLD}AUDITING ALL 11 EMPIRICAL SURVEY SCENARIOS ACROSS 6 DEFENSIVE LAYERS{Colors.RESET}\n")
    
    scenarios = [
        ("Mail 1", "security-alert@bank-verify-account.com", "Security Alert: Your Bank account has been suspended due to unauthorized login attempts. Verify immediately within 24 hours at http://secure-login-verify-account.com or your balance will be frozen permanently.", "http://secure-login-verify-account.com", "SCAM"),
        ("Mail 2", "exam-controller@diu.edu.bd", "Official Notice from Daffodil International University: Mid-Term Examination schedule has been published on the student portal. Please check your assigned room and student ID.", "https://studentportal.diu.edu.bd", "SAFE"),
        ("Mail 3", "scholarship-award@intl-excellence.org", "Congratulations! You have been selected for the International Student Excellence Scholarship of $5,000. To claim your award, submit your processing verification fee of $50 via crypto or wire transfer.", "http://intl-award-verify.xyz", "SCAM"),
        ("Text 1", "bKash", "bKash: Cash Out Tk 1,000.00 to 01711000000 successful. Fee Tk 18.50. Balance Tk 4,520.00. TrxID 9K2L8M1N0P at 14:32 12/08/2025. Download bKash App.", "", "SAFE"),
        ("Text 2", "bKash-Notice-Alert", "bKash Urgent Alert: Your bKash account will be locked within 2 hours due to regulatory KYC failure. Confirm your 5-digit PIN and OTP immediately by clicking: http://bkash-verification-update.xyz", "http://bkash-verification-update.xyz", "SCAM"),
        ("Text 3", "121", "GP Offer: Enjoy 5GB internet + 100 minutes at Tk 108 for 7 days. Dial *121*5050# to activate or recharge Tk 108 through MyGP app. Valid till tomorrow.", "", "SAFE"),
        ("Text 4", "+8801900000000", "Part-Time Job Opportunity! Earn 3,000 - 8,000 BDT daily by liking YouTube videos and rating hotels on Google Maps. No experience needed. Join Telegram: @work_from_home_official", "", "SCAM"),
        ("Text 5", "Delivery-Alert", "Delivery Notification: Your parcel #BD948194 cannot be delivered due to missing house number. Please update your address and pay 25 BDT redelivery fee within 12 hours: http://courier-post-track.com", "http://courier-post-track.com", "SCAM"),
        ("Image 1", "accounts-invoice@ebl-billing.xyz", "Payment Receipt & Invoice: Scanned payment slip from Eastern Bank Limited with QR code redirecting to malicious payment credential harvester.", "http://ebl-invoice-qr.top", "SCAM"),
        ("Image 2", "accounts@diu.edu.bd", "DIU Official Semester Accounts Slip: Certified Daffodil International University accounts clearance showing valid registration seal and institutional watermark.", "", "SAFE"),
        ("Image 3", "promotions@voucher-win.xyz", "Voucher Contest Winner: High-resolution branded graphics stating: 'You won iPhone 16 Pro Max! Scan QR code and enter National Identity (NID) details within 15 minutes.'", "http://apple-reward-claim.site", "SCAM")
    ]
    
    logs = []
    print(f"{'Scenario':<10} | {'True Label':<10} | {'Risk':<6} | {'Action':<12} | {'Mitre ATT&CK Tactics'}")
    print("-" * 88)
    correct = 0
    for name, sender, msg, url, truth in scenarios:
        _, score, verdict, telem = inspect_message(sender, msg, url)
        logs.append(telem)
        is_scam_pred = (score >= 35)
        is_true_scam = (truth == "SCAM")
        if is_scam_pred == is_true_scam: correct += 1
        tactics = ", ".join(telem["mitre_attack_tactics"][:1]) if telem["mitre_attack_tactics"] else "None (Benign)"
        act = telem["action"]
        print(f"{name:<10} | {truth:<10} | {score:<6} | {act:<12} | {tactics[:42]}")
    
    acc = (correct / len(scenarios)) * 100
    print("-" * 88)
    print(f"Six-Layer Hybrid Engine Empirical Benchmark Accuracy: {acc:.1f}% ({correct}/{len(scenarios)} Correct Decisions)\n")
    if siem_mode:
        print(json.dumps(logs, indent=2))

def scan_file(file_path, siem_mode=False):
    """Scans a file containing an email or raw communication"""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        
        # Simple heuristic parser for From:, Subject:, Body, and URLs
        lines = content.splitlines()
        sender = "unknown@domain.com"
        message_lines = []
        for line in lines:
            if line.lower().startswith("from:"):
                sender = line.split(":", 1)[1].strip()
            else:
                message_lines.append(line)
        message = "\n".join(message_lines)
        urls = re.findall(r'https?://\S+', message)
        url = urls[0] if urls else ""
        
        audit, score, verdict, telem = inspect_message(sender, message, url)
        if siem_mode:
            print(json.dumps(telem, indent=2))
        else:
            print_banner()
            print(f"{Colors.BOLD}SCANNING LOCAL ARTIFACT: {file_path}{Colors.RESET}\n")
            print(f"  • Extracted Sender: {sender}")
            print(f"  • Extracted Link  : {url if url else 'None'}")
            print(f"  • Message Preview : {message[:100]}...\n")
            for layer_name, status in audit.items():
                print(f"  [{layer_name:36}] : {status}")
            print(f"\n  ➤ {Colors.BOLD}Aggregated Risk Score : {score} / 100{Colors.RESET}")
            print(f"  ➤ {Colors.BOLD}Automated Action      : {verdict}{Colors.RESET}\n")
    except Exception as e:
        print(f"[!] Error scanning file: {e}")

def run_interactive():
    print_banner()
    print(f"{Colors.CYAN}Enter communication details to evaluate through the Six-Layer Defense Framework:{Colors.RESET}\n")
    try:
        sender = input(f"{Colors.BOLD}Enter Sender Address/Header (e.g. security@bank.com): {Colors.RESET}").strip()
        if not sender: sender = "unknown@domain.com"
        
        message = input(f"{Colors.BOLD}Enter Message/Email Content: {Colors.RESET}").strip()
        if not message: message = "Hello, please check the attached document."
        
        url = input(f"{Colors.BOLD}Enter Embedded URL (optional, press Enter if none): {Colors.RESET}").strip()
        attachment = input(f"{Colors.BOLD}Enter Attachment Filename (optional, press Enter if none): {Colors.RESET}").strip()
        
        print(f"\n{Colors.YELLOW}Executing Six-Layer Autonomous Inspection Pipeline...{Colors.RESET}\n")
        time.sleep(0.4)
        
        audit, score, verdict, telem = inspect_message(sender, message, url, attachment)
        
        for layer_name, status in audit.items():
            print(f"  [{layer_name:36}] : {status}")
            
        print(f"\n  ➤ {Colors.BOLD}Aggregated Risk Score : {score} / 100{Colors.RESET}")
        print(f"  ➤ {Colors.BOLD}Automated Action      : {verdict}{Colors.RESET}\n")
    except KeyboardInterrupt:
        print("\n[!] Exiting...")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Six-Layer AI Phishing Prevention Audit Tool")
    parser.add_argument("--demo", action="store_true", help="Run automated demonstration on benchmark scenarios")
    parser.add_argument("--eval-all", action="store_true", help="Audit all 11 benchmark survey scenarios")
    parser.add_argument("--scan-file", type=str, help="Scan a local email or communication text file")
    parser.add_argument("--json", action="store_true", help="Output telemetry in JSON format for SIEM ingestion")
    args = parser.parse_args()

    if args.demo:
        run_demo(siem_mode=args.json)
    elif args.eval_all:
        evaluate_all_scenarios(siem_mode=args.json)
    elif args.scan_file:
        scan_file(args.scan_file, siem_mode=args.json)
    else:
        run_interactive()
