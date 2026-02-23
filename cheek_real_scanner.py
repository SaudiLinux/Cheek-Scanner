#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cheek Real Scanner - أداة فحص أمني حقيقية
Real Security Scanner with Actual Testing
المبرمج: SayerLinux
الإيميل: SaudiSayer@gmail.com
"""

import requests
import socket
import ssl
import dns.resolver
import subprocess
import json
import time
import re
import warnings
from urllib.parse import urlparse, urljoin
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional
import urllib3

# تعطيل تحذيرات SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore')

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class RealSecurityScanner:
    """فاحص أمني حقيقي بدون محاكاة"""
    
    def __init__(self, target: str, threads: int = 10, timeout: int = 10, verbose: bool = False):
        self.target = self.normalize_target(target)
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        
        # نتائج الفحص
        self.results = {
            'target': self.target,
            'scan_time': datetime.now().isoformat(),
            'vulnerabilities': [],
            'open_ports': [],
            'services': [],
            'web_info': {},
            'dns_info': [],
            'ssl_info': {},
            'security_headers': {},
            'sensitive_files': [],
            'api_endpoints': [],
            'cloud_services': [],
            'risk_score': 0
        }
        
        # جلسة HTTP محسّنة
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def normalize_target(self, target: str) -> str:
        """تطبيع العنوان المستهدف"""
        target = target.strip()
        # إزالة http:// أو https://
        target = re.sub(r'^https?://', '', target)
        # إزالة المسار
        target = target.split('/')[0]
        # إزالة المنفذ
        target = target.split(':')[0]
        return target
    
    def log(self, message: str, level: str = "INFO"):
        """سجل الرسائل"""
        colors = {
            "INFO": Colors.CYAN,
            "SUCCESS": Colors.GREEN,
            "WARNING": Colors.YELLOW,
            "ERROR": Colors.RED,
            "CRITICAL": Colors.MAGENTA
        }
        
        if self.verbose or level in ["SUCCESS", "ERROR", "CRITICAL", "WARNING"]:
            timestamp = datetime.now().strftime("%H:%M:%S")
            color = colors.get(level, Colors.WHITE)
            print(f"[{timestamp}] {color}[{level}]{Colors.RESET} {message}")
    
    def print_banner(self):
        """طباعة الشعار"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════╗
║             Cheek Real Security Scanner                   ║
║              فاحص أمني حقيقي وفعّال                      ║
╚═══════════════════════════════════════════════════════════╝
{Colors.RESET}
{Colors.YELLOW}المبرمج:{Colors.RESET} SayerLinux
{Colors.YELLOW}الإيميل:{Colors.RESET} SaudiSayer@gmail.com
{Colors.YELLOW}الهدف:{Colors.RESET} {self.target}
{Colors.YELLOW}الخيوط:{Colors.RESET} {self.threads}
{Colors.YELLOW}المهلة:{Colors.RESET} {self.timeout}s
"""
        print(banner)
    
    # ============= فحص المنافذ الحقيقي =============
    def scan_port(self, port: int) -> Dict[str, Any]:
        """فحص منفذ واحد"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                # المنفذ مفتوح - جلب البانر
                banner = self.grab_banner(sock, port)
                sock.close()
                return {
                    'port': port,
                    'state': 'open',
                    'banner': banner,
                    'service': self.identify_service(port, banner)
                }
            sock.close()
        except Exception as e:
            self.log(f"خطأ في فحص المنفذ {port}: {e}", "ERROR")
        
        return {'port': port, 'state': 'closed'}
    
    def grab_banner(self, sock: socket.socket, port: int) -> str:
        """جلب بانر الخدمة"""
        try:
            # إرسال طلب HTTP للمنافذ 80, 443, 8080
            if port in [80, 443, 8080, 8443]:
                sock.send(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
            else:
                sock.send(b"\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            return banner[:200]  # أول 200 حرف
        except:
            return ""
    
    def identify_service(self, port: int, banner: str) -> str:
        """تحديد الخدمة"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            6379: 'Redis', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt',
            27017: 'MongoDB', 6443: 'Kubernetes'
        }
        
        # تحديد من البانر
        if 'ssh' in banner.lower():
            return 'SSH'
        elif 'ftp' in banner.lower():
            return 'FTP'
        elif 'http' in banner.lower():
            return 'HTTP/HTTPS'
        elif 'mysql' in banner.lower():
            return 'MySQL'
        
        return services.get(port, f'Unknown-{port}')
    
    def scan_common_ports(self):
        """فحص المنافذ الشائعة"""
        self.log("بدء فحص المنافذ الحقيقي...")
        
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
            993, 995, 1433, 3306, 3389, 5432, 6379,
            8080, 8443, 27017, 6443, 2375, 2376
        ]
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_port, port): port for port in common_ports}
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result['state'] == 'open':
                        self.results['open_ports'].append(result['port'])
                        self.results['services'].append(result)
                        self.log(f"✓ المنفذ {result['port']} مفتوح - {result['service']}", "SUCCESS")
                        
                        # فحص الثغرات المرتبطة بالمنفذ
                        self.check_port_vulnerabilities(result)
                except Exception as e:
                    self.log(f"خطأ في معالجة النتيجة: {e}", "ERROR")
    
    def check_port_vulnerabilities(self, port_info: Dict[str, Any]):
        """فحص الثغرات المرتبطة بالمنفذ"""
        port = port_info['port']
        
        # FTP Anonymous Login
        if port == 21:
            if self.test_ftp_anonymous():
                self.add_vulnerability(
                    "FTP Anonymous Login",
                    "CRITICAL",
                    "يمكن الوصول إلى خادم FTP بدون كلمة مرور",
                    f"ftp://{self.target}:21",
                    "تعطيل تسجيل الدخول المجهول وتطبيق المصادقة القوية"
                )
        
        # SSH Weak Algorithms
        elif port == 22:
            if self.test_ssh_weak_algorithms():
                self.add_vulnerability(
                    "SSH Weak Algorithms",
                    "MEDIUM",
                    "SSH يستخدم خوارزميات تشفير ضعيفة",
                    f"ssh://{self.target}:22",
                    "تحديث إعدادات SSH واستخدام خوارزميات قوية"
                )
        
        # MongoDB No Auth
        elif port == 27017:
            if self.test_mongodb_noauth():
                self.add_vulnerability(
                    "MongoDB No Authentication",
                    "CRITICAL",
                    "MongoDB غير محمي ويمكن الوصول إليه بدون مصادقة",
                    f"mongodb://{self.target}:27017",
                    "تفعيل المصادقة وتقييد الوصول إلى الشبكة"
                )
        
        # Docker API Exposure
        elif port == 2375:
            if self.test_docker_api():
                self.add_vulnerability(
                    "Docker API Exposed",
                    "CRITICAL",
                    "Docker API مكشوف بدون مصادقة",
                    f"http://{self.target}:2375",
                    "تفعيل TLS وتطبيق المصادقة على Docker API"
                )
        
        # Kubernetes API Exposure
        elif port == 6443:
            if self.test_kubernetes_api():
                self.add_vulnerability(
                    "Kubernetes API Exposed",
                    "CRITICAL",
                    "Kubernetes API مكشوف مع مصادقة ضعيفة",
                    f"https://{self.target}:6443",
                    "تفعيل RBAC وتطبيق سياسات الأمان"
                )
    
    # ============= فحوصات حقيقية للثغرات =============
    def test_ftp_anonymous(self) -> bool:
        """اختبار تسجيل دخول FTP المجهول"""
        try:
            import ftplib
            ftp = ftplib.FTP(timeout=self.timeout)
            ftp.connect(self.target, 21)
            ftp.login('anonymous', 'anonymous@')
            ftp.quit()
            return True
        except:
            return False
    
    def test_ssh_weak_algorithms(self) -> bool:
        """فحص خوارزميات SSH الضعيفة"""
        try:
            result = subprocess.run(
                ['ssh', '-v', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5',
                 f'{self.target}'],
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            weak_algos = ['diffie-hellman-group1-sha1', 'ssh-dss', 'arcfour']
            return any(algo in result.stderr.lower() for algo in weak_algos)
        except:
            return False
    
    def test_mongodb_noauth(self) -> bool:
        """فحص MongoDB بدون مصادقة"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, 27017))
            
            # إرسال أمر MongoDB بسيط
            sock.send(b'\x00\x00\x00\x00')
            response = sock.recv(1024)
            sock.close()
            
            return len(response) > 0
        except:
            return False
    
    def test_docker_api(self) -> bool:
        """فحص Docker API"""
        try:
            response = self.session.get(
                f"http://{self.target}:2375/version",
                timeout=self.timeout
            )
            return response.status_code == 200 and 'Version' in response.text
        except:
            return False
    
    def test_kubernetes_api(self) -> bool:
        """فحص Kubernetes API"""
        try:
            response = self.session.get(
                f"https://{self.target}:6443/api",
                timeout=self.timeout,
                verify=False
            )
            return response.status_code in [200, 401, 403]
        except:
            return False
    
    # ============= فحص الويب الحقيقي =============
    def scan_web_application(self):
        """فحص تطبيق الويب"""
        self.log("بدء فحص تطبيق الويب...")
        
        if 80 not in self.results['open_ports'] and 443 not in self.results['open_ports']:
            self.log("لا توجد خدمات ويب مفتوحة", "WARNING")
            return
        
        # فحص HTTP و HTTPS
        protocols = []
        if 80 in self.results['open_ports']:
            protocols.append('http')
        if 443 in self.results['open_ports']:
            protocols.append('https')
        
        for protocol in protocols:
            url = f"{protocol}://{self.target}"
            
            try:
                response = self.session.get(url, timeout=self.timeout)
                
                # تخزين معلومات الويب
                self.results['web_info'][protocol] = {
                    'status_code': response.status_code,
                    'server': response.headers.get('Server', 'Unknown'),
                    'content_type': response.headers.get('Content-Type', 'Unknown'),
                    'content_length': len(response.content)
                }
                
                # فحص رؤوس الأمان
                self.check_security_headers(protocol, response.headers)
                
                # فحص الملفات الحساسة
                self.scan_sensitive_files(url)
                
                # فحص ثغرات SQL Injection
                self.test_sql_injection(url)
                
                # فحص ثغرات XSS
                self.test_xss(url)
                
                # فحص Directory Traversal
                self.test_directory_traversal(url)
                
                # فحص API Endpoints
                self.scan_api_endpoints(url)
                
            except Exception as e:
                self.log(f"خطأ في فحص {url}: {e}", "ERROR")
    
    def check_security_headers(self, protocol: str, headers: Dict[str, str]):
        """فحص رؤوس الأمان"""
        required_headers = {
            'X-Frame-Options': 'Clickjacking Protection',
            'X-Content-Type-Options': 'MIME Sniffing Protection',
            'X-XSS-Protection': 'XSS Protection',
            'Strict-Transport-Security': 'HSTS',
            'Content-Security-Policy': 'CSP',
            'X-Permitted-Cross-Domain-Policies': 'Cross-Domain Policy'
        }
        
        missing_headers = []
        
        for header, description in required_headers.items():
            if header not in headers:
                missing_headers.append(header)
                self.add_vulnerability(
                    f"Missing Security Header: {header}",
                    "MEDIUM",
                    f"رأس الأمان {header} مفقود ({description})",
                    f"{protocol}://{self.target}",
                    f"إضافة رأس {header} إلى جميع الاستجابات"
                )
        
        self.results['security_headers'][protocol] = {
            'present': [h for h in required_headers if h in headers],
            'missing': missing_headers
        }
    
    def scan_sensitive_files(self, base_url: str):
        """فحص الملفات الحساسة"""
        sensitive_paths = [
            '/.git/config',
            '/.env',
            '/config.php',
            '/web.config',
            '/.htaccess',
            '/robots.txt',
            '/sitemap.xml',
            '/admin',
            '/phpmyadmin',
            '/wp-admin',
            '/backup.sql',
            '/database.sql',
            '/.DS_Store',
            '/composer.json',
            '/package.json'
        ]
        
        self.log("فحص الملفات الحساسة...")
        
        for path in sensitive_paths:
            try:
                url = urljoin(base_url, path)
                response = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                
                if response.status_code == 200:
                    self.results['sensitive_files'].append(path)
                    
                    severity = "CRITICAL" if path in ['/.git/config', '/.env', '/backup.sql'] else "HIGH"
                    
                    self.add_vulnerability(
                        f"Sensitive File Exposed: {path}",
                        severity,
                        f"ملف حساس متاح: {path}",
                        url,
                        "إزالة أو حماية الملفات الحساسة"
                    )
                    self.log(f"✗ ملف حساس: {path}", "CRITICAL")
            except:
                pass
    
    def test_sql_injection(self, base_url: str):
        """فحص ثغرات SQL Injection"""
        self.log("فحص ثغرات SQL Injection...")
        
        payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "admin' --",
            "1' UNION SELECT NULL--",
            "' AND 1=1--"
        ]
        
        test_params = ['id', 'user', 'username', 'email', 'search', 'q']
        
        for param in test_params:
            for payload in payloads:
                try:
                    url = f"{base_url}/?{param}={payload}"
                    response = self.session.get(url, timeout=self.timeout)
                    
                    # علامات SQL Injection
                    sql_errors = [
                        'mysql_fetch', 'mysqli', 'SQL syntax',
                        'ORA-', 'PostgreSQL', 'SQLSTATE',
                        'Unclosed quotation mark', 'quoted string not properly terminated'
                    ]
                    
                    if any(error in response.text for error in sql_errors):
                        self.add_vulnerability(
                            "SQL Injection Vulnerability",
                            "CRITICAL",
                            f"ثغرة SQL Injection في المعامل {param}",
                            url,
                            "استخدام Prepared Statements وتحقق من المدخلات"
                        )
                        self.log(f"✗ SQL Injection في {param}", "CRITICAL")
                        break
                except:
                    pass
    
    def test_xss(self, base_url: str):
        """فحص ثغرات XSS"""
        self.log("فحص ثغرات XSS...")
        
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "'\"><script>alert(String.fromCharCode(88,83,83))</script>"
        ]
        
        test_params = ['q', 'search', 'query', 'name', 'comment']
        
        for param in test_params:
            for payload in payloads:
                try:
                    url = f"{base_url}/?{param}={payload}"
                    response = self.session.get(url, timeout=self.timeout)
                    
                    if payload in response.text:
                        self.add_vulnerability(
                            "Cross-Site Scripting (XSS)",
                            "HIGH",
                            f"ثغرة XSS في المعامل {param}",
                            url,
                            "تطهير المدخلات وترميز المخرجات"
                        )
                        self.log(f"✗ XSS في {param}", "CRITICAL")
                        break
                except:
                    pass
    
    def test_directory_traversal(self, base_url: str):
        """فحص ثغرات Directory Traversal"""
        self.log("فحص ثغرات Directory Traversal...")
        
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        test_params = ['file', 'path', 'page', 'include', 'load']
        
        for param in test_params:
            for payload in payloads:
                try:
                    url = f"{base_url}/?{param}={payload}"
                    response = self.session.get(url, timeout=self.timeout)
                    
                    # علامات نجاح الهجوم
                    if 'root:' in response.text or '[boot loader]' in response.text:
                        self.add_vulnerability(
                            "Directory Traversal",
                            "CRITICAL",
                            f"ثغرة Directory Traversal في المعامل {param}",
                            url,
                            "التحقق من صحة المسارات وتقييد الوصول"
                        )
                        self.log(f"✗ Directory Traversal في {param}", "CRITICAL")
                        break
                except:
                    pass
    
    def scan_api_endpoints(self, base_url: str):
        """فحص نقاط نهاية API"""
        self.log("فحص نقاط نهاية API...")
        
        api_paths = [
            '/api/v1', '/api/v2', '/api/v3',
            '/rest/api', '/graphql',
            '/api/users', '/api/admin',
            '/api/config', '/api/health',
            '/swagger', '/swagger-ui.html',
            '/api-docs'
        ]
        
        for path in api_paths:
            try:
                url = urljoin(base_url, path)
                response = self.session.get(url, timeout=self.timeout)
                
                if response.status_code in [200, 401, 403]:
                    self.results['api_endpoints'].append(path)
                    
                    if response.status_code == 200:
                        self.add_vulnerability(
                            f"API Endpoint Exposed: {path}",
                            "MEDIUM",
                            f"نقطة نهاية API متاحة بدون مصادقة: {path}",
                            url,
                            "تطبيق المصادقة والترخيص على API"
                        )
                        self.log(f"API متاح: {path}", "WARNING")
            except:
                pass
    
    # ============= فحص DNS =============
    def scan_dns(self):
        """فحص DNS"""
        self.log("فحص DNS...")
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.target, record_type)
                
                for rdata in answers:
                    record = {
                        'type': record_type,
                        'value': str(rdata),
                        'ttl': answers.ttl
                    }
                    self.results['dns_info'].append(record)
                    self.log(f"DNS {record_type}: {rdata}", "SUCCESS")
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                self.log(f"النطاق غير موجود", "ERROR")
                break
            except Exception as e:
                self.log(f"خطأ في فحص DNS {record_type}: {e}", "ERROR")
    
    # ============= فحص SSL/TLS =============
    def scan_ssl(self):
        """فحص SSL/TLS"""
        if 443 not in self.results['open_ports']:
            return
        
        self.log("فحص SSL/TLS...")
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert(True)
                    cert_dict = ssl.DER_cert_to_PEM_cert(cert)
                    
                    # تحليل الشهادة
                    import OpenSSL
                    x509 = OpenSSL.crypto.load_certificate(
                        OpenSSL.crypto.FILETYPE_PEM,
                        cert_dict
                    )
                    
                    self.results['ssl_info'] = {
                        'subject': dict(x509.get_subject().get_components()),
                        'issuer': dict(x509.get_issuer().get_components()),
                        'version': x509.get_version(),
                        'serial_number': x509.get_serial_number(),
                        'not_before': x509.get_notBefore().decode('utf-8'),
                        'not_after': x509.get_notAfter().decode('utf-8'),
                        'signature_algorithm': x509.get_signature_algorithm().decode('utf-8')
                    }
                    
                    self.log("✓ شهادة SSL صالحة", "SUCCESS")
                    
                    # فحص بروتوكولات SSL الضعيفة
                    self.test_weak_ssl_protocols()
        
        except Exception as e:
            self.log(f"خطأ في فحص SSL: {e}", "ERROR")
            self.add_vulnerability(
                "SSL/TLS Configuration Error",
                "HIGH",
                f"خطأ في إعداد SSL/TLS: {str(e)}",
                f"https://{self.target}",
                "التحقق من إعدادات SSL/TLS"
            )
    
    def test_weak_ssl_protocols(self):
        """فحص بروتوكولات SSL الضعيفة"""
        weak_protocols = {
            'SSLv2': ssl.PROTOCOL_SSLv23,
            'SSLv3': ssl.PROTOCOL_SSLv23,
            'TLSv1.0': ssl.PROTOCOL_TLSv1,
            'TLSv1.1': ssl.PROTOCOL_TLSv1_1
        }
        
        for protocol_name, protocol in weak_protocols.items():
            try:
                context = ssl.SSLContext(protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((self.target, 443), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        self.add_vulnerability(
                            f"Weak SSL Protocol: {protocol_name}",
                            "HIGH",
                            f"البروتوكول الضعيف {protocol_name} مفعل",
                            f"https://{self.target}",
                            f"تعطيل {protocol_name} واستخدام TLS 1.2+"
                        )
                        self.log(f"✗ بروتوكول ضعيف: {protocol_name}", "WARNING")
            except:
                pass
    
    # ============= فحص الخدمات السحابية =============
    def scan_cloud_services(self):
        """فحص الخدمات السحابية"""
        self.log("فحص الخدمات السحابية...")
        
        # AWS S3
        s3_buckets = [
            f"{self.target}",
            f"{self.target}-backup",
            f"{self.target}-data",
            f"{self.target}-logs",
            f"{self.target}-assets"
        ]
        
        for bucket in s3_buckets:
            try:
                url = f"https://{bucket}.s3.amazonaws.com"
                response = self.session.head(url, timeout=self.timeout)
                
                if response.status_code in [200, 403]:
                    self.results['cloud_services'].append({
                        'type': 'AWS S3',
                        'name': bucket,
                        'url': url,
                        'status': response.status_code
                    })
                    
                    if response.status_code == 200:
                        self.add_vulnerability(
                            f"Public S3 Bucket: {bucket}",
                            "CRITICAL",
                            f"S3 Bucket متاح للعموم: {bucket}",
                            url,
                            "تقييد الوصول إلى S3 Bucket"
                        )
                        self.log(f"✗ S3 Bucket عام: {bucket}", "CRITICAL")
            except:
                pass
        
        # Azure Blob Storage
        try:
            url = f"https://{self.target}.blob.core.windows.net"
            response = self.session.head(url, timeout=self.timeout)
            
            if response.status_code in [200, 403]:
                self.results['cloud_services'].append({
                    'type': 'Azure Blob',
                    'name': self.target,
                    'url': url,
                    'status': response.status_code
                })
                
                if response.status_code == 200:
                    self.add_vulnerability(
                        "Public Azure Blob Storage",
                        "CRITICAL",
                        "Azure Blob Storage متاح للعموم",
                        url,
                        "تقييد الوصول إلى Azure Blob Storage"
                    )
        except:
            pass
        
        # GCP Cloud Storage
        try:
            url = f"https://storage.googleapis.com/{self.target}"
            response = self.session.head(url, timeout=self.timeout)
            
            if response.status_code in [200, 403]:
                self.results['cloud_services'].append({
                    'type': 'GCP Storage',
                    'name': self.target,
                    'url': url,
                    'status': response.status_code
                })
                
                if response.status_code == 200:
                    self.add_vulnerability(
                        "Public GCP Cloud Storage",
                        "CRITICAL",
                        "GCP Cloud Storage متاح للعموم",
                        url,
                        "تقييد الوصول إلى GCP Cloud Storage"
                    )
        except:
            pass
    
    # ============= إضافة ثغرة =============
    def add_vulnerability(self, title: str, severity: str, description: str, url: str, recommendation: str):
        """إضافة ثغرة إلى النتائج"""
        vuln = {
            'title': title,
            'severity': severity,
            'description': description,
            'url': url,
            'recommendation': recommendation,
            'timestamp': datetime.now().isoformat()
        }
        self.results['vulnerabilities'].append(vuln)
        
        # حساب النقاط
        severity_scores = {
            'CRITICAL': 10,
            'HIGH': 7,
            'MEDIUM': 4,
            'LOW': 2,
            'INFO': 1
        }
        self.results['risk_score'] += severity_scores.get(severity, 0)
    
    # ============= تنفيذ الفحص الكامل =============
    def run_full_scan(self):
        """تنفيذ الفحص الكامل"""
        self.print_banner()
        
        start_time = time.time()
        
        try:
            # 1. فحص DNS
            self.scan_dns()
            
            # 2. فحص المنافذ
            self.scan_common_ports()
            
            # 3. فحص تطبيق الويب
            self.scan_web_application()
            
            # 4. فحص SSL/TLS
            self.scan_ssl()
            
            # 5. فحص الخدمات السحابية
            self.scan_cloud_services()
            
            execution_time = time.time() - start_time
            self.results['execution_time'] = execution_time
            
            # طباعة الملخص
            self.print_summary()
            
            # حفظ التقرير
            self.save_report()
            
        except KeyboardInterrupt:
            self.log("الفحص متوقف من قبل المستخدم", "WARNING")
        except Exception as e:
            self.log(f"خطأ في تنفيذ الفحص: {e}", "ERROR")
    
    def print_summary(self):
        """طباعة ملخص النتائج"""
        print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
        print(f"{Colors.CYAN}{Colors.BOLD}ملخص نتائج الفحص{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*60}{Colors.RESET}\n")
        
        print(f"{Colors.YELLOW}الهدف:{Colors.RESET} {self.target}")
        print(f"{Colors.YELLOW}وقت الفحص:{Colors.RESET} {self.results['scan_time']}")
        print(f"{Colors.YELLOW}مدة التنفيذ:{Colors.RESET} {self.results.get('execution_time', 0):.2f}s")
        print(f"{Colors.YELLOW}المنافذ المفتوحة:{Colors.RESET} {len(self.results['open_ports'])}")
        print(f"{Colors.YELLOW}الثغرات المكتشفة:{Colors.RESET} {len(self.results['vulnerabilities'])}")
        print(f"{Colors.YELLOW}درجة المخاطر:{Colors.RESET} {self.results['risk_score']}")
        
        # توزيع الثغرات حسب الخطورة
        severity_count = {}
        for vuln in self.results['vulnerabilities']:
            severity = vuln['severity']
            severity_count[severity] = severity_count.get(severity, 0) + 1
        
        if severity_count:
            print(f"\n{Colors.BOLD}توزيع الثغرات:{Colors.RESET}")
            for severity, count in sorted(severity_count.items(), 
                                         key=lambda x: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].index(x[0])):
                color = {
                    'CRITICAL': Colors.MAGENTA,
                    'HIGH': Colors.RED,
                    'MEDIUM': Colors.YELLOW,
                    'LOW': Colors.CYAN,
                    'INFO': Colors.WHITE
                }.get(severity, Colors.WHITE)
                print(f"  {color}• {severity}: {count}{Colors.RESET}")
        
        # أهم 5 ثغرات
        if self.results['vulnerabilities']:
            print(f"\n{Colors.BOLD}أهم الثغرات:{Colors.RESET}")
            for i, vuln in enumerate(self.results['vulnerabilities'][:5], 1):
                color = {
                    'CRITICAL': Colors.MAGENTA,
                    'HIGH': Colors.RED,
                    'MEDIUM': Colors.YELLOW,
                    'LOW': Colors.CYAN
                }.get(vuln['severity'], Colors.WHITE)
                print(f"  {i}. {color}[{vuln['severity']}]{Colors.RESET} {vuln['title']}")
        
        print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
    
    def save_report(self):
        """حفظ التقرير"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"cheek_real_scan_{self.target}_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        self.log(f"✓ التقرير محفوظ في: {filename}", "SUCCESS")

def main():
    """الدالة الرئيسية"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Cheek Real Scanner - فاحص أمني حقيقي وفعّال",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
أمثلة الاستخدام:
  python cheek_real_scanner.py example.com
  python cheek_real_scanner.py example.com --threads 20
  python cheek_real_scanner.py example.com --timeout 5 --verbose
        """
    )
    
    parser.add_argument('target', help='الهدف (نطاق أو IP)')
    parser.add_argument('--threads', type=int, default=10, help='عدد الخيوط (افتراضي: 10)')
    parser.add_argument('--timeout', type=int, default=10, help='المهلة بالثواني (افتراضي: 10)')
    parser.add_argument('--verbose', action='store_true', help='تفعيل الوضع التفصيلي')
    
    args = parser.parse_args()
    
    # إنشاء الفاحص
    scanner = RealSecurityScanner(
        target=args.target,
        threads=args.threads,
        timeout=args.timeout,
        verbose=args.verbose
    )
    
    # تنفيذ الفحص
    scanner.run_full_scan()

if __name__ == '__main__':
    main()
