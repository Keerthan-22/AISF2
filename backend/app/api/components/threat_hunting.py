"""
Continuous Threat Hunting Component
Implements IoC correlation, lateral movement detection, and APT tracking
"""

import json
import hashlib
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_
import asyncio
import aiohttp

from ...models.threat import Threat
from ...core.database import redis
from ..auth.dependencies import get_current_user
from ...models.user import User
from ...core.database import get_db

router = APIRouter(prefix="/threat-hunting", tags=["Threat Hunting"])


class ThreatHuntingEngine:
    """Automates threat hunting queries and IoC correlation."""
    
    def __init__(self):
        self.ioc_patterns = {
            'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
            'md5_hash': r'\b[a-fA-F0-9]{32}\b',
            'sha1_hash': r'\b[a-fA-F0-9]{40}\b',
            'sha256_hash': r'\b[a-fA-F0-9]{64}\b',
            'url': r'https?://[^\s<>"{}|\\^`\[\]]+',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        }
        
        # Threat hunting queries
        self.hunting_queries = {
            'apt_detection': [
                'suspicious_process_creation',
                'unusual_network_connections',
                'data_exfiltration_patterns',
                'persistence_mechanisms'
            ],
            'malware_detection': [
                'file_entropy_analysis',
                'registry_modifications',
                'suspicious_api_calls',
                'network_beaconing'
            ],
            'insider_threat': [
                'unusual_data_access',
                'privilege_escalation',
                'data_transfer_patterns',
                'after_hours_activity'
            ]
        }
    
    async def hunt_threats(self, data_source: str, query_type: str, filters: Dict = None) -> Dict:
        """
        Perform automated threat hunting based on query type.
        """
        try:
            if query_type not in self.hunting_queries:
                raise ValueError(f"Unknown query type: {query_type}")
            
            # Execute hunting queries
            results = []
            for query in self.hunting_queries[query_type]:
                query_result = await self._execute_hunting_query(query, data_source, filters)
                results.extend(query_result)
            
            # Correlate results
            correlated_results = await self._correlate_hunting_results(results)
            
            # Calculate hunting score
            hunting_score = self._calculate_hunting_score(correlated_results)
            
            return {
                'query_type': query_type,
                'data_source': data_source,
                'results': correlated_results,
                'hunting_score': hunting_score,
                'total_findings': len(correlated_results),
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Threat hunting failed: {str(e)}")
    
    async def _execute_hunting_query(self, query: str, data_source: str, filters: Dict) -> List[Dict]:
        """Execute a specific hunting query."""
        # Mock implementation - in real system, this would query actual data sources
        mock_results = []
        
        if query == 'suspicious_process_creation':
            mock_results = [
                {
                    'type': 'process_creation',
                    'severity': 'medium',
                    'description': 'Suspicious process creation detected',
                    'timestamp': datetime.utcnow().isoformat(),
                    'details': {
                        'process_name': 'cmd.exe',
                        'parent_process': 'explorer.exe',
                        'command_line': 'cmd.exe /c powershell.exe -enc ...'
                    }
                }
            ]
        elif query == 'unusual_network_connections':
            mock_results = [
                {
                    'type': 'network_connection',
                    'severity': 'high',
                    'description': 'Unusual outbound connection detected',
                    'timestamp': datetime.utcnow().isoformat(),
                    'details': {
                        'source_ip': '192.168.1.100',
                        'destination_ip': '185.220.101.45',
                        'port': 443,
                        'protocol': 'HTTPS'
                    }
                }
            ]
        elif query == 'data_exfiltration_patterns':
            mock_results = [
                {
                    'type': 'data_exfiltration',
                    'severity': 'critical',
                    'description': 'Large data transfer to external destination',
                    'timestamp': datetime.utcnow().isoformat(),
                    'details': {
                        'data_size': '2.5GB',
                        'destination': 'external_server.com',
                        'file_types': ['docx', 'pdf', 'xlsx']
                    }
                }
            ]
        
        return mock_results
    
    async def _correlate_hunting_results(self, results: List[Dict]) -> List[Dict]:
        """Correlate hunting results to identify patterns."""
        correlated = []
        
        # Group by severity and type
        severity_groups = {}
        for result in results:
            severity = result.get('severity', 'low')
            if severity not in severity_groups:
                severity_groups[severity] = []
            severity_groups[severity].append(result)
        
        # Create correlated findings
        for severity, group_results in severity_groups.items():
            if len(group_results) > 1:
                # Multiple findings of same severity - potential campaign
                correlated.append({
                    'type': 'correlated_finding',
                    'severity': severity,
                    'description': f'Multiple {severity} severity findings detected',
                    'count': len(group_results),
                    'findings': group_results,
                    'timestamp': datetime.utcnow().isoformat()
                })
            else:
                # Single finding
                correlated.extend(group_results)
        
        return correlated
    
    def _calculate_hunting_score(self, results: List[Dict]) -> float:
        """Calculate overall hunting score based on findings."""
        if not results:
            return 0.0
        
        severity_weights = {
            'low': 1.0,
            'medium': 2.0,
            'high': 3.0,
            'critical': 4.0
        }
        
        total_score = 0.0
        for result in results:
            severity = result.get('severity', 'low')
            weight = severity_weights.get(severity, 1.0)
            total_score += weight
        
        # Normalize to 0-100 scale
        max_possible_score = len(results) * 4.0
        hunting_score = (total_score / max_possible_score) * 100
        
        return min(100.0, hunting_score)


class IoCAnalyzer:
    """Analyzes and correlates Indicators of Compromise (IoCs)."""
    
    def __init__(self):
        self.ioc_cache = {}
        self.threat_feeds = {
            'abuseipdb': 'https://api.abuseipdb.com/api/v2/check',
            'virustotal': 'https://www.virustotal.com/vtapi/v2/ip-address/report',
            'alienvault': 'https://otx.alienvault.com/api/v1/indicators/domain/'
        }
    
    async def analyze_iocs(self, data: str) -> Dict:
        """
        Extract and analyze IoCs from data.
        """
        try:
            # Extract IoCs
            extracted_iocs = self._extract_iocs(data)
            
            # Analyze each IoC
            analysis_results = []
            for ioc_type, iocs in extracted_iocs.items():
                for ioc in iocs:
                    analysis = await self._analyze_single_ioc(ioc_type, ioc)
                    analysis_results.append(analysis)
            
            # Correlate IoC findings
            correlation_result = await self._correlate_ioc_findings(analysis_results)
            
            return {
                'extracted_iocs': extracted_iocs,
                'analysis_results': analysis_results,
                'correlation': correlation_result,
                'total_iocs': sum(len(iocs) for iocs in extracted_iocs.values()),
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"IoC analysis failed: {str(e)}")
    
    def _extract_iocs(self, data: str) -> Dict[str, List[str]]:
        """Extract IoCs from data using regex patterns."""
        extracted = {}
        
        for ioc_type, pattern in self.ioc_patterns.items():
            matches = re.findall(pattern, data, re.IGNORECASE)
            if matches:
                # Remove duplicates and normalize
                unique_matches = list(set(matches))
                extracted[ioc_type] = unique_matches
        
        return extracted
    
    async def _analyze_single_ioc(self, ioc_type: str, ioc_value: str) -> Dict:
        """Analyze a single IoC against threat feeds."""
        # Check cache first
        cache_key = f"ioc_analysis:{ioc_type}:{ioc_value}"
        cached_result = await redis.get(cache_key)
        
        if cached_result:
            return json.loads(cached_result)
        
        # Perform analysis
        analysis_result = {
            'ioc_type': ioc_type,
            'ioc_value': ioc_value,
            'threat_score': 0.0,
            'reputation': 'unknown',
            'threat_feeds': {},
            'first_seen': None,
            'last_seen': None
        }
        
        # Check against threat feeds (mock implementation)
        if ioc_type == 'ip_address':
            analysis_result = await self._check_ip_reputation(ioc_value, analysis_result)
        elif ioc_type == 'domain':
            analysis_result = await self._check_domain_reputation(ioc_value, analysis_result)
        elif ioc_type in ['md5_hash', 'sha1_hash', 'sha256_hash']:
            analysis_result = await self._check_hash_reputation(ioc_value, analysis_result)
        
        # Cache result for 1 hour
        await redis.setex(cache_key, 3600, json.dumps(analysis_result))
        
        return analysis_result
    
    async def _check_ip_reputation(self, ip: str, analysis_result: Dict) -> Dict:
        """Check IP reputation against threat feeds."""
        # Mock IP reputation check
        # In real implementation, this would call actual threat feed APIs
        
        # Simulate reputation score
        reputation_score = 0.0
        if ip.startswith('185.220.'):
            reputation_score = 85.0  # Known malicious IP range
        elif ip.startswith('192.168.'):
            reputation_score = 10.0  # Private network
        else:
            reputation_score = 30.0  # Unknown
        
        analysis_result.update({
            'threat_score': reputation_score,
            'reputation': 'malicious' if reputation_score > 70 else 'suspicious' if reputation_score > 30 else 'clean',
            'threat_feeds': {
                'abuseipdb': {'score': reputation_score, 'status': 'found'},
                'virustotal': {'score': reputation_score * 0.8, 'status': 'found'}
            }
        })
        
        return analysis_result
    
    async def _check_domain_reputation(self, domain: str, analysis_result: Dict) -> Dict:
        """Check domain reputation against threat feeds."""
        # Mock domain reputation check
        reputation_score = 0.0
        
        if 'malware' in domain.lower() or 'phishing' in domain.lower():
            reputation_score = 90.0
        elif domain.endswith('.tk') or domain.endswith('.ml'):
            reputation_score = 60.0  # Suspicious TLDs
        else:
            reputation_score = 20.0
        
        analysis_result.update({
            'threat_score': reputation_score,
            'reputation': 'malicious' if reputation_score > 70 else 'suspicious' if reputation_score > 30 else 'clean',
            'threat_feeds': {
                'virustotal': {'score': reputation_score, 'status': 'found'},
                'alienvault': {'score': reputation_score * 0.9, 'status': 'found'}
            }
        })
        
        return analysis_result
    
    async def _check_hash_reputation(self, file_hash: str, analysis_result: Dict) -> Dict:
        """Check file hash reputation against threat feeds."""
        # Mock hash reputation check
        reputation_score = 0.0
        
        # Simulate hash analysis
        if len(file_hash) == 32:  # MD5
            reputation_score = 40.0
        elif len(file_hash) == 40:  # SHA1
            reputation_score = 50.0
        elif len(file_hash) == 64:  # SHA256
            reputation_score = 60.0
        
        analysis_result.update({
            'threat_score': reputation_score,
            'reputation': 'malicious' if reputation_score > 70 else 'suspicious' if reputation_score > 30 else 'clean',
            'threat_feeds': {
                'virustotal': {'score': reputation_score, 'status': 'found'}
            }
        })
        
        return analysis_result
    
    async def _correlate_ioc_findings(self, analysis_results: List[Dict]) -> Dict:
        """Correlate IoC findings to identify patterns."""
        if not analysis_results:
            return {'correlation_score': 0.0, 'patterns': []}
        
        # Calculate overall threat score
        total_score = sum(result.get('threat_score', 0) for result in analysis_results)
        avg_score = total_score / len(analysis_results)
        
        # Identify patterns
        patterns = []
        
        # Check for multiple malicious IoCs
        malicious_iocs = [r for r in analysis_results if r.get('reputation') == 'malicious']
        if len(malicious_iocs) > 1:
            patterns.append({
                'type': 'multiple_malicious_iocs',
                'description': f'Multiple malicious IoCs detected ({len(malicious_iocs)})',
                'severity': 'high'
            })
        
        # Check for IoC types distribution
        ioc_types = {}
        for result in analysis_results:
            ioc_type = result.get('ioc_type')
            if ioc_type not in ioc_types:
                ioc_types[ioc_type] = 0
            ioc_types[ioc_type] += 1
        
        if len(ioc_types) > 2:
            patterns.append({
                'type': 'diverse_ioc_types',
                'description': f'Multiple IoC types detected: {list(ioc_types.keys())}',
                'severity': 'medium'
            })
        
        return {
            'correlation_score': avg_score,
            'patterns': patterns,
            'total_iocs': len(analysis_results),
            'malicious_count': len(malicious_iocs)
        }


class BehavioralAnalysis:
    """Detects lateral movement and insider threats."""
    
    def __init__(self):
        self.behavioral_patterns = {
            'lateral_movement': [
                'unusual_login_patterns',
                'privilege_escalation',
                'network_scanning',
                'service_enumeration'
            ],
            'insider_threat': [
                'unusual_data_access',
                'bulk_data_download',
                'after_hours_activity',
                'privilege_abuse'
            ],
            'data_exfiltration': [
                'large_file_transfers',
                'encrypted_communications',
                'unusual_ports',
                'data_compression'
            ]
        }
    
    async def analyze_behavior(self, user_activity: Dict) -> Dict:
        """
        Analyze user behavior for suspicious patterns.
        """
        try:
            analysis_results = {}
            
            # Analyze each behavioral category
            for category, patterns in self.behavioral_patterns.items():
                category_results = []
                for pattern in patterns:
                    pattern_result = await self._analyze_behavioral_pattern(pattern, user_activity)
                    if pattern_result:
                        category_results.append(pattern_result)
                
                analysis_results[category] = {
                    'patterns_detected': category_results,
                    'risk_score': self._calculate_category_risk(category_results),
                    'severity': self._determine_severity(category_results)
                }
            
            # Calculate overall behavioral risk
            overall_risk = self._calculate_overall_behavioral_risk(analysis_results)
            
            return {
                'behavioral_analysis': analysis_results,
                'overall_risk_score': overall_risk,
                'risk_level': self._get_risk_level(overall_risk),
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Behavioral analysis failed: {str(e)}")
    
    async def _analyze_behavioral_pattern(self, pattern: str, user_activity: Dict) -> Optional[Dict]:
        """Analyze a specific behavioral pattern."""
        # Mock pattern analysis
        # In real implementation, this would analyze actual user activity data
        
        if pattern == 'unusual_login_patterns':
            # Check for unusual login times or locations
            login_times = user_activity.get('login_times', [])
            if len(login_times) > 10:  # Too many logins
                return {
                    'pattern': pattern,
                    'detected': True,
                    'confidence': 0.8,
                    'description': 'Unusual number of login attempts detected',
                    'details': {'login_count': len(login_times)}
                }
        
        elif pattern == 'privilege_escalation':
            # Check for privilege escalation attempts
            privilege_events = user_activity.get('privilege_events', [])
            if privilege_events:
                return {
                    'pattern': pattern,
                    'detected': True,
                    'confidence': 0.9,
                    'description': 'Privilege escalation attempts detected',
                    'details': {'events': privilege_events}
                }
        
        elif pattern == 'unusual_data_access':
            # Check for unusual data access patterns
            data_access = user_activity.get('data_access', {})
            if data_access.get('unusual_files', 0) > 5:
                return {
                    'pattern': pattern,
                    'detected': True,
                    'confidence': 0.7,
                    'description': 'Unusual data access patterns detected',
                    'details': data_access
                }
        
        return None
    
    def _calculate_category_risk(self, category_results: List[Dict]) -> float:
        """Calculate risk score for a behavioral category."""
        if not category_results:
            return 0.0
        
        total_confidence = sum(result.get('confidence', 0) for result in category_results)
        return min(100.0, (total_confidence / len(category_results)) * 100)
    
    def _determine_severity(self, category_results: List[Dict]) -> str:
        """Determine severity level for behavioral category."""
        if not category_results:
            return 'low'
        
        avg_confidence = sum(result.get('confidence', 0) for result in category_results) / len(category_results)
        
        if avg_confidence > 0.8:
            return 'high'
        elif avg_confidence > 0.5:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_overall_behavioral_risk(self, analysis_results: Dict) -> float:
        """Calculate overall behavioral risk score."""
        category_weights = {
            'lateral_movement': 0.4,
            'insider_threat': 0.35,
            'data_exfiltration': 0.25
        }
        
        total_risk = 0.0
        for category, weight in category_weights.items():
            if category in analysis_results:
                category_risk = analysis_results[category]['risk_score']
                total_risk += category_risk * weight
        
        return min(100.0, total_risk)
    
    def _get_risk_level(self, risk_score: float) -> str:
        """Get risk level based on score."""
        if risk_score > 80:
            return 'critical'
        elif risk_score > 60:
            return 'high'
        elif risk_score > 40:
            return 'medium'
        elif risk_score > 20:
            return 'low'
        else:
            return 'minimal'


class ThreatHuntingManager:
    """Manages threat hunting operations and coordinates different analysis components."""
    
    def __init__(self):
        self.hunting_engine = ThreatHuntingEngine()
        self.ioc_analyzer = IoCAnalyzer()
        self.behavioral_analyzer = BehavioralAnalysis()
    
    async def comprehensive_threat_hunt(self, data: Dict, db: AsyncSession) -> Dict:
        """Perform comprehensive threat hunting analysis."""
        try:
            results = {}
            
            # 1. Automated threat hunting
            if 'hunting_queries' in data:
                hunting_results = await self.hunting_engine.hunt_threats(
                    data.get('data_source', 'network'),
                    data.get('query_type', 'apt_detection'),
                    data.get('filters', {})
                )
                results['automated_hunting'] = hunting_results
            
            # 2. IoC analysis
            if 'ioc_data' in data:
                ioc_results = await self.ioc_analyzer.analyze_iocs(data['ioc_data'])
                results['ioc_analysis'] = ioc_results
            
            # 3. Behavioral analysis
            if 'user_activity' in data:
                behavioral_results = await self.behavioral_analyzer.analyze_behavior(data['user_activity'])
                results['behavioral_analysis'] = behavioral_results
            
            # 4. Correlate all findings
            correlation_result = await self._correlate_all_findings(results)
            
            # 5. Store results
            await self._store_hunting_results(results, correlation_result, db)
            
            return {
                'hunting_results': results,
                'correlation': correlation_result,
                'overall_threat_score': correlation_result.get('overall_score', 0.0),
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Comprehensive threat hunting failed: {str(e)}")
    
    async def _correlate_all_findings(self, results: Dict) -> Dict:
        """Correlate findings from all analysis components."""
        overall_score = 0.0
        total_findings = 0
        critical_findings = 0
        
        # Aggregate scores from different components
        if 'automated_hunting' in results:
            hunting_score = results['automated_hunting'].get('hunting_score', 0.0)
            overall_score += hunting_score * 0.4
            total_findings += results['automated_hunting'].get('total_findings', 0)
        
        if 'ioc_analysis' in results:
            ioc_correlation = results['ioc_analysis'].get('correlation', {})
            ioc_score = ioc_correlation.get('correlation_score', 0.0)
            overall_score += ioc_score * 0.35
            total_findings += ioc_correlation.get('total_iocs', 0)
            critical_findings += ioc_correlation.get('malicious_count', 0)
        
        if 'behavioral_analysis' in results:
            behavioral_score = results['behavioral_analysis'].get('overall_risk_score', 0.0)
            overall_score += behavioral_score * 0.25
        
        return {
            'overall_score': min(100.0, overall_score),
            'total_findings': total_findings,
            'critical_findings': critical_findings,
            'risk_level': self._get_overall_risk_level(overall_score)
        }
    
    def _get_overall_risk_level(self, score: float) -> str:
        """Get overall risk level based on comprehensive analysis."""
        if score > 80:
            return 'critical'
        elif score > 60:
            return 'high'
        elif score > 40:
            return 'medium'
        elif score > 20:
            return 'low'
        else:
            return 'minimal'
    
    async def _store_hunting_results(self, results: Dict, correlation: Dict, db: AsyncSession):
        """Store hunting results in database."""
        # Store as a threat record
        threat_record = Threat(
            type='hunting_result',
            confidence=correlation.get('overall_score', 0.0),
            source='threat_hunting',
            status='investigating',
            response_plan=json.dumps({
                'hunting_results': results,
                'correlation': correlation
            })
        )
        
        db.add(threat_record)
        await db.commit()


# Initialize components
hunting_engine = ThreatHuntingEngine()
ioc_analyzer = IoCAnalyzer()
behavioral_analyzer = BehavioralAnalysis()
threat_hunting_manager = ThreatHuntingManager()

# API Endpoints
@router.post("/hunt-threats")
async def hunt_threats(
    data_source: str = "network",
    query_type: str = "apt_detection",
    filters: Dict = None,
    current_user: User = Depends(get_current_user)
):
    """Perform automated threat hunting based on query type."""
    try:
        result = await hunting_engine.hunt_threats(data_source, query_type, filters or {})
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Threat hunting failed: {str(e)}")

@router.post("/ioc-analysis")
async def analyze_iocs(
    data: str,
    current_user: User = Depends(get_current_user)
):
    """Analyze Indicators of Compromise (IoCs) from data."""
    try:
        result = await ioc_analyzer.analyze_iocs(data)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"IoC analysis failed: {str(e)}")

@router.post("/behavioral-analysis")
async def analyze_behavior(
    user_activity: Dict,
    current_user: User = Depends(get_current_user)
):
    """Analyze user behavior for suspicious patterns."""
    try:
        result = await behavioral_analyzer.analyze_behavior(user_activity)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Behavioral analysis failed: {str(e)}")

@router.post("/comprehensive-hunt")
async def comprehensive_threat_hunt(
    data: Dict,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Perform comprehensive threat hunting across all components."""
    try:
        result = await threat_hunting_manager.comprehensive_threat_hunt(data, db)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Comprehensive threat hunting failed: {str(e)}")

@router.get("/hunting-queries")
async def get_available_queries(
    current_user: User = Depends(get_current_user)
):
    """Get available threat hunting query types."""
    return {
        "available_queries": list(hunting_engine.hunting_queries.keys()),
        "query_descriptions": {
            "apt_detection": "Advanced Persistent Threat detection queries",
            "malware_detection": "Malware and suspicious file analysis",
            "insider_threat": "Insider threat and privilege abuse detection"
        }
    } 