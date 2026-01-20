"""
Security Scoring System
Calculates overall security scores and risk levels based on findings
"""

from typing import Dict, List
from datetime import datetime


class SecurityScorer:
    """
    Calculates security scores based on vulnerability findings
    """
    
    def __init__(self):
        """Initialize scoring weights"""
        # Point deductions per severity level
        self.severity_weights = {
            'CRITICAL': 25,  # Each critical finding deducts 25 points
            'HIGH': 15,      # Each high finding deducts 15 points
            'MEDIUM': 8,     # Each medium finding deducts 8 points
            'LOW': 3         # Each low finding deducts 3 points
        }
        
        # Risk level thresholds
        self.risk_thresholds = {
            'SECURE': (90, 100),      # 90-100 = Secure
            'LOW_RISK': (70, 89),     # 70-89 = Low Risk
            'MEDIUM_RISK': (50, 69),  # 50-69 = Medium Risk
            'HIGH_RISK': (30, 49),    # 30-49 = High Risk
            'CRITICAL': (0, 29)       # 0-29 = Critical
        }
    
    def calculate_score(self, findings: Dict) -> Dict:
        """
        Calculate overall security score from findings
        
        Args:
            findings: Dictionary with severity breakdown
                     e.g., {'CRITICAL': 2, 'HIGH': 3, 'MEDIUM': 1, 'LOW': 0}
        
        Returns:
            Score details including overall score, risk level, and breakdown
        """
        # Start with perfect score
        base_score = 100
        
        # Deduct points for each finding
        total_deduction = 0
        deduction_breakdown = {}
        
        for severity, count in findings.items():
            if severity in self.severity_weights and count > 0:
                deduction = self.severity_weights[severity] * count
                total_deduction += deduction
                deduction_breakdown[severity] = {
                    'count': count,
                    'points_per_finding': self.severity_weights[severity],
                    'total_deduction': deduction
                }
        
        # Calculate final score (minimum 0)
        final_score = max(0, base_score - total_deduction)
        
        # Determine risk level
        risk_level = self._get_risk_level(final_score)
        
        # Get risk color for display
        risk_color = self._get_risk_color(risk_level)
        
        # Calculate total findings
        total_findings = sum(findings.values())
        
        return {
            'score': final_score,
            'risk_level': risk_level,
            'risk_color': risk_color,
            'total_findings': total_findings,
            'severity_breakdown': findings,
            'deduction_breakdown': deduction_breakdown,
            'total_deduction': total_deduction,
            'timestamp': datetime.now().isoformat(),
            'grade': self._get_letter_grade(final_score),
            'status_emoji': self._get_status_emoji(risk_level)
        }
    
    def _get_risk_level(self, score: int) -> str:
        """Determine risk level based on score"""
        for level, (min_score, max_score) in self.risk_thresholds.items():
            if min_score <= score <= max_score:
                return level
        return 'UNKNOWN'
    
    def _get_risk_color(self, risk_level: str) -> str:
        """Get color code for risk level"""
        colors = {
            'SECURE': 'green',
            'LOW_RISK': 'blue',
            'MEDIUM_RISK': 'yellow',
            'HIGH_RISK': 'orange',
            'CRITICAL': 'red'
        }
        return colors.get(risk_level, 'gray')
    
    def _get_letter_grade(self, score: int) -> str:
        """Convert numeric score to letter grade"""
        if score >= 95:
            return 'A+'
        elif score >= 90:
            return 'A'
        elif score >= 85:
            return 'A-'
        elif score >= 80:
            return 'B+'
        elif score >= 75:
            return 'B'
        elif score >= 70:
            return 'B-'
        elif score >= 65:
            return 'C+'
        elif score >= 60:
            return 'C'
        elif score >= 55:
            return 'C-'
        elif score >= 50:
            return 'D'
        else:
            return 'F'
    
    def _get_status_emoji(self, risk_level: str) -> str:
        """Get emoji for risk level"""
        emojis = {
            'SECURE': '🟢',
            'LOW_RISK': '🔵',
            'MEDIUM_RISK': '🟡',
            'HIGH_RISK': '🟠',
            'CRITICAL': '🔴'
        }
        return emojis.get(risk_level, '⚪')
    
    def get_recommendation(self, score_details: Dict) -> str:
        """
        Get security recommendation based on score
        
        Args:
            score_details: Output from calculate_score()
        
        Returns:
            Recommendation text
        """
        risk_level = score_details['risk_level']
        
        recommendations = {
            'SECURE': (
                "Excellent security posture! Your AI system demonstrates strong security controls. "
                "Continue monitoring for new vulnerabilities and maintain current security practices."
            ),
            'LOW_RISK': (
                "Good security posture with minor issues. Address the identified LOW severity "
                "findings to achieve optimal security. Consider implementing additional security "
                "controls as a proactive measure."
            ),
            'MEDIUM_RISK': (
                "Moderate security concerns detected. Priority should be given to addressing MEDIUM "
                "and HIGH severity findings. Implement input validation, output sanitization, and "
                "secure credential management practices."
            ),
            'HIGH_RISK': (
                "Significant security vulnerabilities detected. Immediate action required to address "
                "HIGH and CRITICAL findings. These vulnerabilities could be exploited to compromise "
                "your AI system. Implement security fixes before production deployment."
            ),
            'CRITICAL': (
                "URGENT: Critical security vulnerabilities detected. DO NOT deploy to production. "
                "Multiple severe issues require immediate remediation. Consider engaging security "
                "experts to review and harden your AI system before proceeding."
            )
        }
        
        return recommendations.get(risk_level, "Review findings and implement recommended fixes.")
    
    def generate_report_summary(self, score_details: Dict) -> str:
        """
        Generate a formatted text summary of the security score
        
        Args:
            score_details: Output from calculate_score()
        
        Returns:
            Formatted summary string
        """
        lines = []
        lines.append("="*60)
        lines.append("🔒 SECURITY SCORE REPORT")
        lines.append("="*60)
        lines.append("")
        lines.append(f"{score_details['status_emoji']} Overall Score: {score_details['score']}/100 (Grade: {score_details['grade']})")
        lines.append(f"📊 Risk Level: {score_details['risk_level'].replace('_', ' ')}")
        lines.append(f"🔍 Total Findings: {score_details['total_findings']}")
        lines.append("")
        lines.append("Severity Breakdown:")
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = score_details['severity_breakdown'].get(severity, 0)
            if count > 0:
                emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}[severity]
                lines.append(f"  {emoji} {severity}: {count}")
        
        if score_details['deduction_breakdown']:
            lines.append("")
            lines.append("Point Deductions:")
            for severity, details in score_details['deduction_breakdown'].items():
                lines.append(
                    f"  {severity}: {details['count']} × {details['points_per_finding']} = "
                    f"-{details['total_deduction']} points"
                )
        
        lines.append("")
        lines.append("="*60)
        lines.append("Recommendation:")
        lines.append(self.get_recommendation(score_details))
        lines.append("="*60)
        
        return "\n".join(lines)


def calculate_security_score(severity_breakdown: Dict) -> Dict:
    """
    Convenience function to calculate security score
    
    Args:
        severity_breakdown: Dict with severity counts
    
    Returns:
        Complete score details
    """
    scorer = SecurityScorer()
    return scorer.calculate_score(severity_breakdown)