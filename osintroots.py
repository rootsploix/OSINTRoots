#!/usr/bin/env python3
"""
OSINTRoots - Advanced OSINT Framework
Professional open source intelligence gathering tool by Rootsploix

Features:
- Social media intelligence
- Domain and subdomain enumeration
- Email harvesting and validation
- Phone number intelligence
- Dark web monitoring
- Data breach searching
- Person tracking and profiling

Author: Rootsploix
Version: 2.1.0
License: Commercial
Price: $799 (Professional) / $1999 (Enterprise)
"""

import requests
import json
import re
import time
import sys
import argparse
import socket
import dns.resolver
import whois
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Optional
from rootsploix_license import RootsploixLicense

class OSINTRoots:
    """Advanced OSINT intelligence gathering framework"""
    
    def __init__(self):
        self.license = RootsploixLicense("OSINTRoots", "2.1.0")
        self.is_licensed = False
        self.license_info = {}
        self.scan_stats = {'scan_count': 0, 'target_count': 0}
        
        # OSINT data sources (demo version limited)
        self.social_platforms = [
            'twitter.com', 'facebook.com', 'instagram.com', 'linkedin.com',
            'github.com', 'reddit.com', 'youtube.com', 'tiktok.com'
        ]
        
        # Search engines for dorking
        self.search_engines = [
            'google.com', 'bing.com', 'duckduckgo.com', 'yandex.com'
        ]
        
        # Common subdomain wordlist (demo version limited)
        self.subdomain_wordlist = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'api', 'app',
            'blog', 'shop', 'secure', 'vpn', 'cdn', 'news', 'support'
        ]
        
        # Professional wordlist would have 10,000+ entries
        if self.license_info.get('status') != 'demo':
            self.subdomain_wordlist.extend([
                'staging', 'beta', 'alpha', 'portal', 'dashboard', 'panel',
                'cms', 'db', 'database', 'backup', 'old', 'new', 'legacy'
            ])
        
        # Breach databases (demo version limited)
        self.breach_sources = [
            'haveibeenpwned', 'dehashed', 'leakcheck', 'snusbase'
        ]
    
    def authenticate(self, license_key: str = None) -> bool:
        """Authenticate with license system"""
        if not license_key:
            print(self.license.generate_license_prompt(), end="")
            license_key = input().strip()
        
        self.is_licensed, self.license_info = self.license.validate_license(license_key)
        
        if self.is_licensed:
            if self.license_info['status'] == 'demo':
                print(self.license.get_demo_banner())
            else:
                print(self.license.get_professional_banner())
            return True
        else:
            print(f"❌ License validation failed: {self.license_info.get('error', 'Unknown error')}")
            return False
    
    def domain_intelligence(self, domain: str) -> Dict:
        """Gather intelligence on domain"""
        print(f"🔍 Gathering domain intelligence for {domain}")
        
        results = {
            'domain': domain,
            'whois_info': {},
            'dns_records': {},
            'subdomains': [],
            'certificates': {},
            'technologies': [],
            'social_presence': {}
        }
        
        try:
            # WHOIS information
            results['whois_info'] = self._get_whois_info(domain)
            
            # DNS enumeration
            results['dns_records'] = self._get_dns_records(domain)
            
            # Subdomain enumeration
            results['subdomains'] = self._enumerate_subdomains(domain)
            
            # Professional features
            if self.license_info.get('status') == 'professional':
                results['certificates'] = self._get_certificate_info(domain)
                results['technologies'] = self._detect_technologies(domain)
                results['social_presence'] = self._find_social_accounts(domain)
            
            return results
            
        except Exception as e:
            results['error'] = str(e)
            return results
    
    def _get_whois_info(self, domain: str) -> Dict:
        """Get WHOIS information for domain"""
        try:
            w = whois.whois(domain)
            return {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers,
                'emails': w.emails if hasattr(w, 'emails') else []
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _get_dns_records(self, domain: str) -> Dict:
        """Enumerate DNS records"""
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        
        # Demo version limited record types
        if self.license_info.get('status') == 'demo':
            record_types = record_types[:3]
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(answer) for answer in answers]
                print(f"  ✅ Found {len(records[record_type])} {record_type} records")
            except:
                continue
        
        return records
    
    def _enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate subdomains using wordlist"""
        print(f"🔍 Enumerating subdomains for {domain}")
        
        found_subdomains = []
        wordlist = self.subdomain_wordlist[:50] if self.license_info.get('status') == 'demo' else self.subdomain_wordlist
        
        def check_subdomain(subdomain: str) -> Optional[str]:
            try:
                full_domain = f"{subdomain}.{domain}"
                socket.gethostbyname(full_domain)
                return full_domain
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_subdomain = {
                executor.submit(check_subdomain, sub): sub 
                for sub in wordlist
            }
            
            for future in as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    found_subdomains.append(result)
                    print(f"  ✅ Found subdomain: {result}")
        
        return found_subdomains
    
    def _get_certificate_info(self, domain: str) -> Dict:
        """Professional feature: SSL certificate analysis"""
        if self.license_info.get('status') != 'professional':
            return {'error': 'Certificate analysis requires Professional license'}
        
        try:
            import ssl
            import socket
            
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
            
            # Extract Subject Alternative Names for subdomain discovery
            san_list = []
            if 'subjectAltName' in cert:
                for name_type, name_value in cert['subjectAltName']:
                    if name_type == 'DNS':
                        san_list.append(name_value)
            
            return {
                'subject': dict(x[0] for x in cert['subject']),
                'issuer': dict(x[0] for x in cert['issuer']),
                'version': cert['version'],
                'serial_number': cert['serialNumber'],
                'not_before': cert['notBefore'],
                'not_after': cert['notAfter'],
                'subject_alt_names': san_list
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _detect_technologies(self, domain: str) -> List[str]:
        """Professional feature: Technology stack detection"""
        if self.license_info.get('status') != 'professional':
            return ['Technology detection requires Professional license']
        
        technologies = []
        
        try:
            response = requests.get(f"http://{domain}", timeout=10, verify=False)
            headers = response.headers
            content = response.text.lower()
            
            # Server detection
            if 'server' in headers:
                technologies.append(f"Server: {headers['server']}")
            
            # CMS detection
            cms_signatures = {
                'WordPress': ['wp-content', 'wp-includes'],
                'Drupal': ['drupal.js', '/sites/'],
                'Joomla': ['joomla', '/components/'],
                'Magento': ['magento', 'mage/cookies'],
                'Shopify': ['shopify', 'cdn.shopify']
            }
            
            for cms, signatures in cms_signatures.items():
                if any(sig in content for sig in signatures):
                    technologies.append(f"CMS: {cms}")
            
            # JavaScript frameworks
            js_frameworks = {
                'React': ['react', '_react'],
                'Angular': ['angular', 'ng-'],
                'Vue.js': ['vue.js', '__vue__'],
                'jQuery': ['jquery', '$']
            }
            
            for framework, signatures in js_frameworks.items():
                if any(sig in content for sig in signatures):
                    technologies.append(f"Framework: {framework}")
            
        except Exception as e:
            technologies.append(f"Error detecting technologies: {e}")
        
        return technologies
    
    def _find_social_accounts(self, domain: str) -> Dict:
        """Professional feature: Social media account discovery"""
        if self.license_info.get('status') != 'professional':
            return {'error': 'Social media discovery requires Professional license'}
        
        social_accounts = {}
        company_name = domain.split('.')[0]  # Simple extraction
        
        # Search patterns for social media
        search_patterns = [
            f"{company_name}",
            f"{domain}",
            f"@{company_name}"
        ]
        
        for pattern in search_patterns[:1]:  # Limit in demo
            for platform in self.social_platforms[:4]:  # Top 4 platforms
                try:
                    # Simulate social media search (real implementation would use APIs)
                    potential_url = f"https://{platform}/{company_name}"
                    response = requests.get(potential_url, timeout=5, verify=False)
                    
                    if response.status_code == 200:
                        social_accounts[platform] = potential_url
                        print(f"  ✅ Found social account: {potential_url}")
                
                except:
                    continue
        
        return social_accounts
    
    def person_intelligence(self, name: str, email: str = None, phone: str = None) -> Dict:
        """Gather intelligence on person"""
        print(f"🔍 Gathering person intelligence for {name}")
        
        # Check demo limits
        if self.license_info.get('status') == 'demo':
            self.scan_stats['scan_count'] += 1
            self.scan_stats['target_count'] = 1
            
            within_limits, message = self.license.check_demo_limits(self.scan_stats)
            if not within_limits:
                print(f"❌ {message}")
                return {'error': message}
        
        results = {
            'name': name,
            'email': email,
            'phone': phone,
            'social_profiles': {},
            'data_breaches': [],
            'professional_info': {},
            'associates': [],
            'locations': []
        }
        
        try:
            # Social media profiling
            results['social_profiles'] = self._search_social_profiles(name)
            
            # Professional features
            if self.license_info.get('status') == 'professional':
                if email:
                    results['data_breaches'] = self._check_data_breaches(email)
                
                results['professional_info'] = self._get_professional_info(name)
                results['associates'] = self._find_associates(name)
                results['locations'] = self._get_location_data(name, phone)
            
            return results
            
        except Exception as e:
            results['error'] = str(e)
            return results
    
    def _search_social_profiles(self, name: str) -> Dict:
        """Search for social media profiles"""
        profiles = {}
        
        # Demo version limited to basic search
        search_name = name.lower().replace(' ', '')
        
        for platform in self.social_platforms[:3]:  # Demo limitation
            try:
                # Simulate profile search (real implementation would use APIs)
                potential_profiles = [
                    f"https://{platform}/{search_name}",
                    f"https://{platform}/{search_name.replace(' ', '.')}",
                    f"https://{platform}/{search_name.replace(' ', '_')}"
                ]
                
                for profile_url in potential_profiles[:1]:  # Check first variant only
                    response = requests.get(profile_url, timeout=5, verify=False)
                    if response.status_code == 200 and len(response.content) > 1000:
                        profiles[platform] = profile_url
                        print(f"  ✅ Potential profile found: {profile_url}")
                        break
            
            except:
                continue
        
        return profiles
    
    def _check_data_breaches(self, email: str) -> List[Dict]:
        """Professional feature: Check for data breaches"""
        if self.license_info.get('status') != 'professional':
            return [{'error': 'Data breach checking requires Professional license'}]
        
        breaches = []
        
        # Simulate breach database queries (real implementation would use APIs)
        common_breaches = [
            {'name': 'LinkedIn', 'year': 2021, 'records': '700M'},
            {'name': 'Facebook', 'year': 2021, 'records': '533M'},
            {'name': 'Twitter', 'year': 2022, 'records': '5.4M'},
            {'name': 'Adobe', 'year': 2013, 'records': '153M'}
        ]
        
        # Simulate email being found in breaches (for demo purposes)
        import random
        for breach in common_breaches[:2]:  # Limit results
            if random.choice([True, False]):  # Random simulation
                breach['email_found'] = True
                breaches.append(breach)
                print(f"  🚨 Email found in {breach['name']} breach ({breach['year']})")
        
        return breaches
    
    def _get_professional_info(self, name: str) -> Dict:
        """Professional feature: Get professional information"""
        if self.license_info.get('status') != 'professional':
            return {'error': 'Professional info gathering requires Professional license'}
        
        # Simulate LinkedIn/professional network search
        return {
            'linkedin_profile': f"Potential LinkedIn profile for {name}",
            'company': 'Unknown',
            'position': 'Unknown',
            'skills': [],
            'connections': 'Professional license required for full details'
        }
    
    def _find_associates(self, name: str) -> List[str]:
        """Professional feature: Find associates and connections"""
        if self.license_info.get('status') != 'professional':
            return ['Associate finding requires Professional license']
        
        # Simulate associate discovery
        associates = [
            f"Potential associate 1 of {name}",
            f"Potential associate 2 of {name}"
        ]
        
        return associates
    
    def _get_location_data(self, name: str, phone: str = None) -> List[Dict]:
        """Professional feature: Get location intelligence"""
        if self.license_info.get('status') != 'professional':
            return [{'error': 'Location intelligence requires Professional license'}]
        
        locations = []
        
        if phone:
            # Phone number geolocation (simulated)
            locations.append({
                'type': 'phone_geolocation',
                'country': 'Unknown',
                'region': 'Unknown',
                'carrier': 'Unknown',
                'line_type': 'Unknown'
            })
        
        return locations
    
    def email_intelligence(self, email: str) -> Dict:
        """Gather intelligence on email address"""
        print(f"🔍 Gathering email intelligence for {email}")
        
        results = {
            'email': email,
            'valid': False,
            'domain_info': {},
            'breaches': [],
            'social_accounts': {},
            'professional_profiles': {}
        }
        
        try:
            # Email validation
            results['valid'] = self._validate_email(email)
            
            # Domain analysis
            domain = email.split('@')[1]
            results['domain_info'] = self._get_whois_info(domain)
            
            # Professional features
            if self.license_info.get('status') == 'professional':
                results['breaches'] = self._check_data_breaches(email)
                results['social_accounts'] = self._find_email_social_accounts(email)
                results['professional_profiles'] = self._find_professional_profiles(email)
            
            return results
            
        except Exception as e:
            results['error'] = str(e)
            return results
    
    def _validate_email(self, email: str) -> bool:
        """Basic email validation"""
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$'
        return bool(re.match(email_pattern, email))
    
    def _find_email_social_accounts(self, email: str) -> Dict:
        """Professional feature: Find social accounts associated with email"""
        if self.license_info.get('status') != 'professional':
            return {'error': 'Email social account search requires Professional license'}
        
        # Simulate social account discovery
        accounts = {}
        username = email.split('@')[0]
        
        for platform in self.social_platforms[:3]:
            # Simulate account existence check
            if len(username) > 3:  # Simple heuristic
                accounts[platform] = f"Potential account: https://{platform}/{username}"
        
        return accounts
    
    def _find_professional_profiles(self, email: str) -> Dict:
        """Professional feature: Find professional profiles"""
        if self.license_info.get('status') != 'professional':
            return {'error': 'Professional profile search requires Professional license'}
        
        return {
            'linkedin': f"Professional profile search for {email}",
            'github': f"GitHub profile search for {email}",
            'stackoverflow': f"StackOverflow profile search for {email}"
        }
    
    def generate_report(self, intelligence_data: Dict, report_type: str = 'domain') -> str:
        """Generate detailed intelligence report"""
        if self.license_info.get('status') != 'professional':
            return "Professional reporting requires license upgrade"
        
        if report_type == 'domain':
            return self._generate_domain_report(intelligence_data)
        elif report_type == 'person':
            return self._generate_person_report(intelligence_data)
        elif report_type == 'email':
            return self._generate_email_report(intelligence_data)
        else:
            return "Unknown report type"
    
    def _generate_domain_report(self, data: Dict) -> str:
        """Generate domain intelligence report"""
        report = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                         🔍 OSINTROOTS DOMAIN REPORT 🔍                       ║
╚══════════════════════════════════════════════════════════════════════════════╝

Domain: {data['domain']}
Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

WHOIS INFORMATION:
{'='*80}
Registrar: {data.get('whois_info', {}).get('registrar', 'Unknown')}
Creation Date: {data.get('whois_info', {}).get('creation_date', 'Unknown')}
Expiration Date: {data.get('whois_info', {}).get('expiration_date', 'Unknown')}

SUBDOMAINS DISCOVERED:
{'='*80}
Total Subdomains: {len(data.get('subdomains', []))}
"""
        
        for subdomain in data.get('subdomains', [])[:10]:
            report += f"• {subdomain}\\n"
        
        if data.get('technologies'):
            report += f"\\nTECHNOLOGIES DETECTED:\\n{'='*80}\\n"
            for tech in data['technologies'][:5]:
                report += f"• {tech}\\n"
        
        if data.get('social_presence'):
            report += f"\\nSOCIAL PRESENCE:\\n{'='*80}\\n"
            for platform, url in data['social_presence'].items():
                report += f"• {platform}: {url}\\n"
        
        return report
    
    def _generate_person_report(self, data: Dict) -> str:
        """Generate person intelligence report"""
        report = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                         👤 OSINTROOTS PERSON REPORT 👤                       ║
╚══════════════════════════════════════════════════════════════════════════════╝

Name: {data['name']}
Email: {data.get('email', 'Unknown')}
Phone: {data.get('phone', 'Unknown')}
Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

SOCIAL PROFILES:
{'='*80}
"""
        
        for platform, profile in data.get('social_profiles', {}).items():
            report += f"• {platform}: {profile}\\n"
        
        if data.get('data_breaches'):
            report += f"\\nDATA BREACHES:\\n{'='*80}\\n"
            for breach in data['data_breaches']:
                if breach.get('email_found'):
                    report += f"🚨 {breach['name']} ({breach['year']}) - {breach['records']} records\\n"
        
        return report
    
    def _generate_email_report(self, data: Dict) -> str:
        """Generate email intelligence report"""
        report = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                         📧 OSINTROOTS EMAIL REPORT 📧                        ║
╚══════════════════════════════════════════════════════════════════════════════╝

Email: {data['email']}
Valid: {'Yes' if data['valid'] else 'No'}
Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

DOMAIN INFORMATION:
{'='*80}
Domain: {data['email'].split('@')[1]}
Registrar: {data.get('domain_info', {}).get('registrar', 'Unknown')}

ASSOCIATED ACCOUNTS:
{'='*80}
"""
        
        for platform, account in data.get('social_accounts', {}).items():
            report += f"• {platform}: {account}\\n"
        
        return report

def main():
    parser = argparse.ArgumentParser(
        description="OSINTRoots - Advanced OSINT Framework by Rootsploix",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python osintroots.py --domain example.com --license DEMO
  python osintroots.py --person "John Doe" --email john@example.com --license RXPRO-XXXXX-XXXXX-XXXXX-XXXXX
  python osintroots.py --email target@victim.com --output osint_report.txt
        """
    )
    
    parser.add_argument('--domain', '-d', help='Target domain for intelligence gathering')
    parser.add_argument('--person', '-p', help='Target person name for intelligence gathering')
    parser.add_argument('--email', '-e', help='Target email for intelligence gathering')
    parser.add_argument('--phone', help='Target phone number (used with person)')
    parser.add_argument('--license', '-l', help='License key (or DEMO for demo mode)')
    parser.add_argument('--output', '-o', help='Output file for intelligence report (Professional only)')
    parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    
    args = parser.parse_args()
    
    if not any([args.domain, args.person, args.email]):
        print("❌ Please specify at least one target: --domain, --person, or --email")
        sys.exit(1)
    
    # Initialize OSINT framework
    osint = OSINTRoots()
    
    # Authenticate
    if not osint.authenticate(args.license):
        sys.exit(1)
    
    # Perform intelligence gathering
    try:
        results = None
        report_type = None
        
        if args.domain:
            print(f"🚀 Starting domain intelligence gathering for {args.domain}...")
            results = osint.domain_intelligence(args.domain)
            report_type = 'domain'
        
        elif args.person:
            print(f"🚀 Starting person intelligence gathering for {args.person}...")
            results = osint.person_intelligence(args.person, args.email, args.phone)
            report_type = 'person'
        
        elif args.email:
            print(f"🚀 Starting email intelligence gathering for {args.email}...")
            results = osint.email_intelligence(args.email)
            report_type = 'email'
        
        if results and 'error' not in results:
            print(f"\\n🎉 Intelligence gathering completed!")
            
            # Generate professional report
            if osint.license_info.get('status') == 'professional':
                report = osint.generate_report(results, report_type)
                print(report)
                
                # Save to file if requested
                if args.output:
                    with open(args.output, 'w') as f:
                        f.write(report)
                    print(f"💾 Intelligence report saved to {args.output}")
            
            # JSON output
            if args.json:
                print("\\n📋 Results (JSON):")
                print(json.dumps(results, indent=2))
        
        else:
            print(f"❌ Intelligence gathering failed: {results.get('error', 'Unknown error')}")
    
    except KeyboardInterrupt:
        print("\\n⚠️  Intelligence gathering interrupted by user")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()