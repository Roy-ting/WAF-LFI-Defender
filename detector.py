import re
import urllib.parse

class FileInclusionDetector:
    def __init__(self):
        # 定义规则库 (正则表达式)
        self.rules = {
            "Path Traversal": r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%2e%2e%5c)",
            "PHP Wrapper": r"(php://|file://|data://|zip://|phar://)",
            "Sensitive Files": r"(/etc/passwd|/etc/shadow|C:\\Windows\\win.ini|/proc/self/environ)",
            "Null Byte": r"(%00|\x00)"
        }

    def decode_payload(self, payload):
        """对 payload 进行 URL 解码，防止编码绕过"""
        if not payload:
            return ""
        decoded = urllib.parse.unquote(payload)
        decoded = urllib.parse.unquote(decoded) # 二次解码防绕过
        return decoded

    def check_payload(self, payload):
        """检测单个参数值"""
        decoded_payload = self.decode_payload(payload)
        
        for rule_name, pattern in self.rules.items():
            if re.search(pattern, decoded_payload, re.IGNORECASE):
                return True, rule_name, decoded_payload
        return False, None, None

    def scan_request(self, args_dict, form_dict):
        """扫描整个请求的所有参数"""
        all_params = {**args_dict, **form_dict}
        
        for key, value in all_params.items():
            is_attack, rule_name, decoded_val = self.check_payload(str(value))
            if is_attack:
                return True, {
                    "parameter": key,
                    "payload": decoded_val,
                    "rule_matched": rule_name
                }
        return False, None