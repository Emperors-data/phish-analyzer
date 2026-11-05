def make_finding(category, points, message):
    return {'category': category, 'points': points, 'message': message}
    
def defang(text):
    return text.replace('http', 'hxxp').replace('.', '[.]')
    
def related(a, b):
    return a == b or a.endswith('.' + b) or b.endswith('.' + a)
