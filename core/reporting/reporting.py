from typing import Dict


class ReportGenerator:
    def draft_report(self, findings: Dict[str, str]) -> Dict[str, str]:
        return {
            "summary": findings.get("summary", "Investigación inicial de endpoint sospechoso."),
            "impact": findings.get("impact", "Posible falta de validación de autorización en API o recurso.") ,
            "reproduction": findings.get("reproduction", "Recolectar endpoints, roles e intentar acceso con diferentes cuentas."),
            "severity": findings.get("severity", "medium"),
        }
