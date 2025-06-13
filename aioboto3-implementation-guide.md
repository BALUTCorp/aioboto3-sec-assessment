# Implementation Guide: aioboto3 Security for Vietnamese Enterprises
## Hướng dẫn triển khai bảo mật aioboto3 cho doanh nghiệp Việt Nam

---

## 1. Quick Start Security Setup (30 phút)

### Bước 1: Cài đặt Security Tools
```bash
# Cài đặt các công cụ bảo mật cơ bản
pip install safety bandit pip-audit semgrep

# Cài đặt môi trường secure development
pip install pre-commit secretlint detect-secrets
```

### Bước 2: Tạo Security Configuration
```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          pip install safety bandit pip-audit
          pip install -r requirements.txt
      
      - name: Safety check
        run: safety check --json --output safety-report.json
        
      - name: Bandit security scan
        run: bandit -r . -f json -o bandit-report.json
        
      - name: Pip audit
        run: pip-audit --desc --format=json --output=pip-audit-report.json
```

### Bước 3: Secure Code Template
```python
# secure_aws_client.py - Template cho enterprise use
import logging
import asyncio
from typing import Optional, Dict, Any
import aioboto3
from botocore.exceptions import ClientError, BotoCoreError

class SecureAWSClient:
    """
    Enterprise-grade secure wrapper cho aioboto3
    Tuân thủ các tiêu chuẩn bảo mật doanh nghiệp Việt Nam
    """
    
    def __init__(self, 
                 service_name: str,
                 region_name: str = 'ap-southeast-1',  # Singapore region cho VN
                 enable_audit_logging: bool = True):
        self.service_name = service_name
        self.region_name = region_name
        self.enable_audit_logging = enable_audit_logging
        self.session = None
        self.client = None
        
        # Setup audit logging
        if enable_audit_logging:
            self.audit_logger = self._setup_audit_logger()
    
    def _setup_audit_logger(self):
        """Cấu hình audit logging theo chuẩn doanh nghiệp"""
        logger = logging.getLogger(f'aws_audit.{self.service_name}')
        logger.setLevel(logging.INFO)
        
        # Format log theo chuẩn audit trail
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - '
            'User: %(user)s - Action: %(action)s - Resource: %(resource)s - '
            'Result: %(result)s - %(message)s'
        )
        
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    async def __aenter__(self):
        """Secure session initialization với error handling"""
        try:
            self.session = aioboto3.Session()
            self.client = await self.session.client(
                self.service_name,
                region_name=self.region_name
            ).__aenter__()
            
            if self.enable_audit_logging:
                self.audit_logger.info(
                    "AWS session established",
                    extra={
                        'user': 'system',
                        'action': 'session_start',
                        'resource': f'{self.service_name}:{self.region_name}',
                        'result': 'success'
                    }
                )
            
            return self
            
        except Exception as e:
            if self.enable_audit_logging:
                self.audit_logger.error(
                    f"Failed to establish AWS session: {str(e)}",
                    extra={
                        'user': 'system',
                        'action': 'session_start',
                        'resource': f'{self.service_name}:{self.region_name}',
                        'result': 'failure'
                    }
                )
            raise
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Secure session cleanup"""
        if self.client:
            await self.client.__aexit__(exc_type, exc_val, exc_tb)
        
        if self.enable_audit_logging:
            result = 'success' if exc_type is None else 'failure'
            self.audit_logger.info(
                "AWS session terminated",
                extra={
                    'user': 'system',
                    'action': 'session_end',
                    'resource': f'{self.service_name}:{self.region_name}',
                    'result': result
                }
            )
    
    async def safe_execute(self, operation: str, **kwargs) -> Optional[Dict[Any, Any]]:
        """
        Execute AWS operation với comprehensive error handling và audit logging
        """
        start_time = asyncio.get_event_loop().time()
        
        try:
            # Pre-execution validation
            self._validate_operation_params(operation, kwargs)
            
            # Execute operation
            operation_func = getattr(self.client, operation)
            result = await operation_func(**kwargs)
            
            # Log successful operation
            if self.enable_audit_logging:
                execution_time = asyncio.get_event_loop().time() - start_time
                self.audit_logger.info(
                    f"Operation {operation} completed successfully",
                    extra={
                        'user': 'system',
                        'action': operation,
                        'resource': str(kwargs.get('Bucket', kwargs.get('TableName', 'unknown')),
                        'result': 'success',
                        'execution_time': f'{execution_time:.3f}s'
                    }
                )
            
            return result
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            
            if self.enable_audit_logging:
                self.audit_logger.warning(
                    f"AWS ClientError: {error_code} - {error_message}",
                    extra={
                        'user': 'system',
                        'action': operation,
                        'resource': str(kwargs.get('Bucket', kwargs.get('TableName', 'unknown')),
                        'result': 'client_error',
                        'error_code': error_code
                    }
                )
            
            # Re-raise for application handling
            raise
            
        except BotoCoreError as e:
            if self.enable_audit_logging:
                self.audit_logger.error(
                    f"BotoCoreError: {str(e)}",
                    extra={
                        'user': 'system',
                        'action': operation,
                        'resource': str(kwargs.get('Bucket', kwargs.get('TableName', 'unknown')),
                        'result': 'botocore_error'
                    }
                )
            raise
            
        except Exception as e:
            if self.enable_audit_logging:
                self.audit_logger.error(
                    f"Unexpected error: {str(e)}",
                    extra={
                        'user': 'system',
                        'action': operation,
                        'resource': str(kwargs.get('Bucket', kwargs.get('TableName', 'unknown')),
                        'result': 'unexpected_error'
                    }
                )
            raise
    
    def _validate_operation_params(self, operation: str, params: Dict[str, Any]):
        """Validate operation parameters trước khi execute"""
        # Implement validation logic based on enterprise security policies
        pass

# Usage example
async def example_secure_s3_operations():
    """Ví dụ sử dụng secure client"""
    async with SecureAWSClient('s3') as aws_client:
        # List buckets với audit logging
        buckets = await aws_client.safe_execute('list_buckets')
        
        # Upload file với validation
        await aws_client.safe_execute(
            'put_object',
            Bucket='my-enterprise-bucket',
            Key='secure-file.txt',
            Body=b'Enterprise data'
        )
```

---

## 2. Enterprise Security Policies

### 2.1 Dependency Management Policy
```toml
# pyproject.toml - Enterprise configuration
[tool.enterprise-security]
allowed_licenses = ["Apache-2.0", "MIT", "BSD-3-Clause"]
blocked_packages = ["requests<2.31.0", "urllib3<2.0.0"]
security_scan_required = true
vulnerability_threshold = "HIGH"

[tool.safety]
ignore = []  # Không ignore vulnerabilities trong production
audit_level = "all"

[tool.bandit]
exclude_dirs = ["tests", "venv", ".venv"]
severity_level = "medium"
```

### 2.2 CI/CD Security Pipeline
```yaml
# .github/workflows/enterprise-security.yml
name: Enterprise Security Pipeline
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Dependency vulnerability scan
        run: |
          pip install safety
          safety check --json --output safety-report.json
          
      - name: Static security analysis
        run: |
          pip install bandit
          bandit -r . -f json -o bandit-report.json
          
      - name: License compliance check
        run: |
          pip install pip-licenses
          pip-licenses --format=json --output-file=licenses.json
          
      - name: Secrets detection
        run: |
          pip install detect-secrets
          detect-secrets scan --all-files --baseline .secrets.baseline
          
      - name: Upload security reports
        uses: actions/upload-artifact@v4
        with:
          name: security-reports
          path: |
            safety-report.json
            bandit-report.json
            licenses.json
  
  compliance-check:
    runs-on: ubuntu-latest
    needs: security-scan
    steps:
      - name: SOC 2 compliance validation
        run: |
          # Implement SOC 2 compliance checks
          echo "Validating SOC 2 requirements..."
          
      - name: PDPA compliance check
        run: |
          # Vietnam Personal Data Protection compliance
          echo "Checking PDPA compliance..."
```

---

## 3. Monitoring & Alerting Setup

### 3.1 Security Monitoring Dashboard
```python
# monitoring/security_dashboard.py
import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List

class SecurityMonitor:
    """Security monitoring cho aioboto3 usage"""
    
    def __init__(self):
        self.alerts = []
        self.metrics = {}
    
    async def monitor_aws_operations(self):
        """Monitor AWS operations cho suspicious activities"""
        while True:
            try:
                # Check for unusual patterns
                await self.check_rate_limits()
                await self.check_failed_authentications()
                await self.check_data_access_patterns()
                
                # Sleep for monitoring interval
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                print(f"Monitoring error: {e}")
                await asyncio.sleep(300)  # Wait 5 minutes on error
    
    async def check_rate_limits(self):
        """Check for API rate limit violations"""
        # Implement rate limit monitoring
        pass
    
    async def check_failed_authentications(self):
        """Monitor authentication failures"""
        # Implement auth failure monitoring
        pass
    
    async def check_data_access_patterns(self):
        """Monitor unusual data access patterns"""
        # Implement data access monitoring
        pass
    
    def generate_security_report(self) -> Dict:
        """Generate daily security report"""
        return {
            'date': datetime.now().isoformat(),
            'alerts_count': len(self.alerts),
            'metrics': self.metrics,
            'compliance_status': 'compliant'
        }
```

### 3.2 Alert Configuration
```yaml
# alerts/config.yml
security_alerts:
  high_priority:
    - event: "authentication_failure"
      threshold: 5
      window: "5m"
      action: ["email", "slack", "pagerduty"]
      
    - event: "unusual_data_access"
      ml_detection: true
      action: ["email", "slack"]
      
    - event: "rate_limit_exceeded"
      threshold: 100
      window: "1m"
      action: ["email"]
  
  medium_priority:
    - event: "dependency_vulnerability"
      severity: ["HIGH", "CRITICAL"]
      action: ["email"]
      
    - event: "license_violation"
      action: ["email", "block_deployment"]

notification_channels:
  email:
    recipients: ["security@company.vn", "devops@company.vn"]
    
  slack:
    webhook: "${SLACK_SECURITY_WEBHOOK}"
    channel: "#security-alerts"
    
  pagerduty:
    integration_key: "${PAGERDUTY_INTEGRATION_KEY}"
```

---

## 4. Compliance & Audit Framework

### 4.1 Vietnamese Regulatory Compliance
```python
# compliance/vietnam_regulations.py
class VietnamComplianceChecker:
    """
    Compliance checker cho các quy định Việt Nam:
    - Luật An toàn thông tin mạng 2015
    - Nghị định 85/2016/NĐ-CP về bảo vệ dữ liệu cá nhân
    - Thông tư 20/2017/TT-BTTTT về tiêu chuẩn kỹ thuật bảo mật
    """
    
    def __init__(self):
        self.compliance_rules = {
            'data_localization': True,  # Dữ liệu cá nhân phải lưu trữ tại VN
            'encryption_required': True,  # Mã hóa dữ liệu bắt buộc
            'audit_logging': True,  # Ghi log audit bắt buộc
            'access_control': True,  # Kiểm soát truy cập nghiêm ngặt
        }
    
    def check_data_localization(self, region: str) -> bool:
        """Check if data is stored in Vietnam or approved regions"""
        approved_regions = ['ap-southeast-1']  # Singapore for Vietnamese companies
        return region in approved_regions
    
    def validate_encryption(self, encryption_config: Dict) -> bool:
        """Validate encryption meets Vietnamese standards"""
        required_algorithms = ['AES-256', 'RSA-2048']
        return any(alg in str(encryption_config) for alg in required_algorithms)
    
    def audit_compliance_status(self) -> Dict:
        """Generate compliance audit report"""
        return {
            'compliant': True,
            'last_check': datetime.now().isoformat(),
            'violations': [],
            'recommendations': []
        }
```

### 4.2 Audit Trail Implementation
```python
# audit/trail.py
import json
from datetime import datetime
from typing import Dict, Any

class AuditTrail:
    """Comprehensive audit trail cho enterprise compliance"""
    
    def __init__(self, output_file: str = "audit_trail.jsonl"):
        self.output_file = output_file
    
    def log_event(self, 
                  event_type: str,
                  user_id: str,
                  resource: str,
                  action: str,
                  result: str,
                  additional_data: Dict[str, Any] = None):
        """Log security event cho audit trail"""
        
        event = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event_id': self._generate_event_id(),
            'event_type': event_type,
            'user_id': user_id,
            'resource': resource,
            'action': action,
            'result': result,
            'source_ip': self._get_source_ip(),
            'user_agent': self._get_user_agent(),
            'additional_data': additional_data or {}
        }
        
        # Write to audit log file
        with open(self.output_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(event, ensure_ascii=False) + '\n')
    
    def _generate_event_id(self) -> str:
        import uuid
        return str(uuid.uuid4())
    
    def _get_source_ip(self) -> str:
        # Implement IP detection logic
        return "127.0.0.1"
    
    def _get_user_agent(self) -> str:
        # Implement user agent detection
        return "aioboto3-enterprise-client/1.0"
```

---

## 5. Training & Documentation

### 5.1 Developer Security Training Checklist
```markdown
## Checklist đào tạo bảo mật cho Developer

### Module 1: AWS Security Fundamentals
- [ ] IAM best practices
- [ ] S3 bucket security configuration  
- [ ] CloudTrail logging
- [ ] KMS encryption

### Module 2: aioboto3 Secure Coding
- [ ] Proper session management
- [ ] Error handling security
- [ ] Credential management
- [ ] Async security patterns

### Module 3: Vietnamese Compliance
- [ ] Luật An toàn thông tin mạng
- [ ] Bảo vệ dữ liệu cá nhân
- [ ] Tiêu chuẩn kỹ thuật bảo mật

### Module 4: Incident Response
- [ ] Phát hiện sự cố bảo mật
- [ ] Quy trình báo cáo
- [ ] Recovery procedures
- [ ] Post-incident analysis
```

### 5.2 Security Runbook
```markdown
## Security Incident Response Runbook

### 1. Phát hiện sự cố (Detection)
- Monitor logs và alerts
- Xác định mức độ nghiêm trọng
- Kích hoạt response team

### 2. Containment
- Isolate affected systems
- Prevent further damage
- Preserve evidence

### 3. Eradication  
- Remove threat
- Apply patches
- Update security controls

### 4. Recovery
- Restore services
- Monitor for reoccurrence
- Validate fixes

### 5. Lessons Learned
- Document incident
- Update procedures
- Improve security controls
```

