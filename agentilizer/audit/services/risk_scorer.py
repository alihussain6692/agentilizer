def compute_combined_score(ede_risk: str, gdpr_flag: bool,
                           aibom_risk: str, aibom_available: bool) -> str:
    score_map = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'MINIMAL': 0, 'UNKNOWN': 0}
    scores = [score_map.get(ede_risk.upper(), 0)]
    if gdpr_flag:
        scores.append(3)  # GDPR flag is at least HIGH
    if aibom_available:
        scores.append(score_map.get(aibom_risk.upper(), 0))
    labels = ['MINIMAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    return labels[min(max(scores), 4)]
