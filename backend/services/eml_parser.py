"""
EML Parser
Parses .eml email files and extracts subject, sender, body, URLs
"""

import re
import email
from email import policy
from email.parser import BytesParser
from email.policy import default
from typing import Dict, List, Optional
from html import unescape


class EMLParser:
    def __init__(self, max_body_length: int = 10000):
        self.max_body_length = max_body_length
    
    def parse_file(self, file_path: str) -> Dict:
        """Parse .eml file and extract components."""
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=default).parse(f)
        
        return self._extract_components(msg)
    
    def parse_content(self, content: str) -> Dict:
        """Parse raw .eml content string."""
        msg = email.message_from_string(content, policy=default)
        
        return self._extract_components(msg)
    
    def _extract_components(self, msg) -> Dict:
        """Extract subject, sender, body, URLs from message."""
        subject = self._get_subject(msg)
        sender = self._get_sender(msg)
        body = self._get_body(msg)
        urls = self._extract_urls(body)
        
        return {
            "subject": subject,
            "sender": sender,
            "body": body,
            "urls": urls,
            "subject_clean": self._clean_text(subject),
            "body_clean": self._clean_text(body),
            "text_combined": self._clean_text(subject) + " " + self._clean_text(body)
        }
    
    def _get_subject(self, msg) -> str:
        """Extract subject line."""
        subject = msg.get('Subject', '')
        if subject:
            subject = email.header.decode_header(subject)
            if isinstance(subject, list):
                subject = ' '.join([
                    part.decode(charset or 'utf-8') if isinstance(part, bytes) else str(part)
                    for part, charset in subject
                ])
        return str(subject)
    
    def _get_sender(self, msg) -> str:
        """Extract sender email address."""
        from_header = msg.get('From', '')
        
        match = re.search(r'<(.+?)>|([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+)', from_header)
        if match:
            return match.group(1) or match.group(2)
        
        return from_header
    
    def _get_body(self, msg) -> str:
        """Extract email body (plain text or HTML)."""
        body_text = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == 'text/plain' and not body_text:
                    body_text = self._get_part_content(part)
                elif content_type == 'text/html' and not body_text:
                    body_text = self._get_part_content(part)
        else:
            body_text = self._get_part_content(msg)
        
        body_text = unescape(body_text)
        
        if len(body_text) > self.max_body_length:
            body_text = body_text[:self.max_body_length]
        
        return body_text
    
    def _get_part_content(self, part) -> str:
        """Get content from message part."""
        try:
            content = part.get_content()
            if isinstance(content, str):
                return content
            return str(content)
        except:
            return part.get_payload(decode=True).decode('utf-8', errors='ignore') if part.get_payload(decode=True) else ""
    
    def _extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text."""
        url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
            re.IGNORECASE
        )
        
        urls = url_pattern.findall(text)
        
        unique_urls = list(dict.fromkeys(urls))
        
        return unique_urls[:20]
    
    def _clean_text(self, text: str) -> str:
        """Clean text for ML processing."""
        if not text:
            return ""
        
        text = text.lower()
        
        text = re.sub(r'<[^>]+>', ' ', text)
        
        text = re.sub(r'http[s]?://\S+', ' url ', text)
        
        text = re.sub(r'[^\w\s]', ' ', text)
        
        text = re.sub(r'\s+', ' ', text)
        
        return text.strip()


def parse_eml_file(file_path: str, max_body_length: int = 10000) -> Dict:
    """Parse .eml file - main function."""
    parser = EMLParser(max_body_length=max_body_length)
    return parser.parse_file(file_path)


def parse_eml_content(content: str, max_body_length: int = 10000) -> Dict:
    """Parse .eml content string - main function."""
    parser = EMLParser(max_body_length=max_body_length)
    return parser.parse_content(content)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        result = parse_eml_file(sys.argv[1])
        print("Subject:", result['subject'])
        print("Sender:", result['sender'])
        print("URLs:", result['urls'])
        print("Body (first 200 chars):", result['body'][:200])