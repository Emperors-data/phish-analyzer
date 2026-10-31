def calculate_score(findings):
    return min(100, sum(f['points'] for f in findings))
    

def verdict(score):
    if score >= 60:
       return 'High RISK - likely phishing'
    if score >= 30:
       return 'SUSPICIOUS - needs manual review'
    return 'LOW RISK - no strong indicators'
