-- users
DROP TABLE IF EXISTS server_logs;
CREATE TABLE server_logs(
    ip TEXT,
    timestamp TEXT,
    http_method TEXT,
    path TEXT,
    status_code INT,
    size INT,
    referrer TEXT,
    user_agent TEXT
);

-- SELECT ip, COUNT(*) as request_count
-- FROM server_logs
-- WHERE timestamp >= datetime('now', '-10 minutes')
-- GROUP BY ip
-- HAVING request_count > 100; 

-- SELECT strftime('%Y-%m-%d %H:00:00', timestamp) as hour, COUNT(*) as hits
-- FROM server_logs
-- GROUP BY hour
-- ORDER BY hour DESC;

SELECT ip
FROM server_logs
WHERE strftime('%Y-%m-%d', timestamp) = '2025-04-17';


SELECT COUNT(*)
FROM server_logs
WHERE date = ?;

SELECT COUNT(*) as requests_count
FROM server_logs
WHERE strftime('%Y-%m-%d', timestamp) = '2025-04-17';

SELECT strftime('%Y-%m-%d %H:00:00', timestamp) as hour, COUNT(*) as request_count
FROM server_logs
WHERE timestamp >= datetime('2025-04-17' + '+1 day')
GROUP BY hour
ORDER BY hour;

SELECT CAST(ROUND(AVG(size)) as int) as 'average_size'
FROM server_logs
WHERE strftime('%Y-%m-%d', timestamp) = '2025-04-17';


SELECT COUNT(DISTINCT ip)
FROM server_logs;

SELECT COUNT(*) as status_code_count
FROM server_logs
GROUP BY substr(status_code, 1,1);



SELECT COUNT(*), strftime('%H', timestamp) as hour FROM server_logs
WHERE strftime('%Y-%m-%d', timestamp) = '2025-05-01' AND status_code >= 400 and status_code < 500
GROUP BY hour;

SELECT COUNT(*), strftime('%H', timestamp) as hour FROM server_logs
WHERE strftime('%Y-%m-%d', timestamp) = '2025-05-01' AND status_code >= 100 and status_code < 200
GROUP BY hour;

SELECT COUNT(*), strftime('%H', timestamp) as hour FROM server_logs
WHERE strftime('%Y-%m-%d', timestamp) = '2025-05-01' AND status_code >= 200 and status_code < 300
GROUP BY hour;

SELECT COUNT(*), strftime('%H', timestamp) as hour FROM server_logs
WHERE strftime('%Y-%m-%d', timestamp) = '2025-05-01' AND status_code >= 300 and status_code < 400
GROUP BY hour;

  SELECT COUNT(*) as count, strftime('%H', timestamp) as hour
        FROM server_logs
        WHERE strftime('%Y-%m-%d', timestamp) = '2025-04-20' AND status_code >= 500 and status_code < 600
        GROUP BY hour;      