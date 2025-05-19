from datetime import datetime, timedelta
from sqlite3 import Connection
import numpy as np
import statistics

from map import get_address


def get_number_of_ips(db: Connection, date: str | None = "2025-05-18"):
    return db.execute(
        """
        SELECT COUNT(DISTINCT ip) AS total_ips
        FROM server_logs
        WHERE strftime('%Y-%m-%d', timestamp) = ?;
        """,
        (date,),
    ).fetchone()


def get_traffic_spikes(db, date):

    # Get hourly request counts
    rows = db.execute(
        """
        SELECT COUNT(*) AS count
        FROM server_logs
        WHERE date(timestamp) = ?
        GROUP BY strftime('%H', timestamp)
    """,
        (date,),
    ).fetchall()

    counts = [row["count"] for row in rows]

    # Step 2: Calculate mean and std deviation
    mean = np.mean(counts)
    std_dev = np.std(counts)

    upper_threshold = mean + 2 * std_dev
    lower_threshold = mean - 2 * std_dev

    # Get the traffic spikes and dips
    spikes = db.execute(
        """
    SELECT strftime('%H', timestamp) as hour, COUNT(*) as count
    FROM server_logs 
    WHERE strftime('%Y-%m-%d', timestamp) = ?
    GROUP BY hour
    HAVING COUNT(*) > ? OR 
    COUNT(*) < ?
    """,
        (date, upper_threshold, lower_threshold),
    ).fetchall()

    # Convert SQLite Row objects to dicts
    results = [{"hour": row["hour"], "count": row["count"]} for row in spikes]

    return results


def get_max_date(db: Connection):
    date_object = db.execute(
        """
        SELECT MAX(strftime('%Y-%m-%d', timestamp)) as date
        FROM server_logs;
        """
    ).fetchone()

    return date_object["date"]


def get_total_logs(db: Connection, date: str | None = "2025-05-18"):
    total_logs_object = db.execute(
        """
        SELECT COUNT(*) AS total_logs
        FROM server_logs
        WHERE strftime('%Y-%m-%d', timestamp) = ?;
        """,
        (date,),
    ).fetchone()

    return total_logs_object["total_logs"]


def get_status_code(db: Connection, date: str):
    status_codes = db.execute(
        """
        SELECT substr(status_code, 1, 1) || 'xx' as status_class, COUNT(*) as status_code_count
        FROM server_logs
        WHERE strftime('%Y-%m-%d', timestamp) = ?
        GROUP BY status_class;
        """,
        (date,),
    ).fetchall()

    print(status_codes)

    return {row["status_class"]: row["status_code_count"] for row in status_codes}


def get_ip_comparison(db, date_str):
    # Convert date string to date object
    date = datetime.strptime(date_str, "%Y-%m-%d").date()
    prev_date = date - timedelta(days=1)

    rows = db.execute(
        """
        SELECT 
            strftime('%Y-%m-%d', timestamp) as day,
            COUNT(DISTINCT ip) as total_ips
        FROM server_logs
        WHERE day IN (?, ?)
        GROUP BY day
        """,
        (str(date), str(prev_date)),
    ).fetchall()

    # Map results to dict
    result = {row["day"]: row["total_ips"] for row in rows}
    current = result.get(str(date), 0)
    previous = result.get(str(prev_date), 0)

    # Calculate percentage change
    try:
        percent_change = ((current - previous) / previous) * 100
    except ZeroDivisionError:
        percent_change = 0 if current == 0 else 100  # 100% increase from 0

    return {"total_ips": current, "percent_change": percent_change}


def get_status_code_bar_data(db: Connection, date: str):
    statusCode5XX = db.execute(
        """
        SELECT COUNT(*) as count, strftime('%H', timestamp) as hour
        FROM server_logs
        WHERE strftime('%Y-%m-%d', timestamp) = ? AND status_code >= 500 and status_code < 600
        GROUP BY hour;            
        """,
        (date,),
    ).fetchall()

    statusCode4XX = db.execute(
        """
        SELECT COUNT(*) as count, strftime('%H', timestamp) as hour
        FROM server_logs
        WHERE strftime('%Y-%m-%d', timestamp) = ? AND status_code >= 400 and status_code < 500
        GROUP BY hour;            
        """,
        (date,),
    ).fetchall()

    statusCode3XX = db.execute(
        """
        SELECT COUNT(*) as count, strftime('%H', timestamp) as hour
        FROM server_logs
        WHERE strftime('%Y-%m-%d', timestamp) = ? AND status_code >= 200 and status_code < 300
        GROUP BY hour;            
        """,
        (date,),
    ).fetchall()

    statusCode2XX = db.execute(
        """
        SELECT COUNT(*) as count, strftime('%H', timestamp) as hour
        FROM server_logs
        WHERE strftime('%Y-%m-%d', timestamp) = ? AND status_code >= 200 and status_code < 300
        GROUP BY hour;            
        """,
        (date,),
    ).fetchall()

    data = {
        "2xx": [0 for _ in range(24)],
        "3xx": [0 for _ in range(24)],
        "4xx": [0 for _ in range(24)],
        "5xx": [0 for _ in range(24)],
    }

    for code in statusCode2XX:
        code["hour"]
        data["2xx"][int(code["hour"])] = code["count"]
    for code in statusCode3XX:
        code["hour"]
        data["3xx"][int(code["hour"])] = code["count"]
    for code in statusCode4XX:
        code["hour"]
        data["4xx"][int(code["hour"])] = code["count"]
    for code in statusCode5XX:
        code["hour"]
        data["5xx"][int(code["hour"])] = code["count"]

    return data


def get_traffic_for_day(db: Connection, date: str):
    hours = db.execute(
        """
        SELECT strftime('%H', timestamp) as hour, COUNT(*) as count
        FROM server_logs 
        WHERE strftime('%Y-%m-%d', timestamp) = ?
        GROUP BY hour
        """,
        (date,),
    ).fetchall()

    # Convert SQLite Row objects to lists of values
    times = {"hours": [0 for _ in range(24)]}

    for hour in hours:
        hour_str = hour["hour"]
        times["hours"][int(hour_str)] = hour["count"]

    return times


def get_avg_response_size(db: Connection, date: str):
    avg_response_size = db.execute(
        """
    SELECT 
        strftime('%H', timestamp) AS hour,
        AVG(size) AS average_size
    FROM server_logs
    WHERE strftime('%Y-%m-%d', timestamp) = ?
    GROUP BY hour
    ORDER BY hour;
    """,
        (date,),
    ).fetchall()

    sizes = {"hours": [0 for _ in range(24)]}
    for hour in avg_response_size:
        hour_str = hour["hour"]
        sizes["hours"][int(hour_str)] = hour["average_size"]

    return sizes


def get_top_endPoints(db: Connection, date: str):
    top_endpoints = db.execute(
        """
        SELECT path AS path, COUNT(*) as count
        FROM server_logs
        WHERE strftime('%Y-%m-%d', timestamp) = ?
        GROUP BY path
        ORDER BY count DESC
        LIMIT 4;
        """,
        (date,),
    ).fetchall()

    # ok

    endPoints = {"paths": [], "count": []}
    for endpoint in top_endpoints:
        endPoints["paths"].append(endpoint["path"])
        endPoints["count"].append(endpoint["count"])

    return endPoints


def get_visual_map_data(db: Connection, date):

    ips_counter = {}

    ips = db.execute(
        """
        SELECT DISTINCT ip
        FROM server_logs
        WHERE strftime('%Y-%m-%d', timestamp) = ?;
        """,
        (date,),
    ).fetchall()

    ip_list = [ip_tuple[0] for ip_tuple in ips]

    for ip in ip_list:

        location_data = get_address(str(ip))
        key = (location_data["id"], location_data["name"])

        if key in ips_counter:
            ips_counter[key] += 1
        else:
            ips_counter[key] = 1

    formatted_output = []

    for country in ips_counter:
        formatted_output.append(
            {"id": country[0], "name": country[1], "value": ips_counter[country]}
        )
    return formatted_output


def get_error_rate(db: Connection, date: str):
    num_errors = db.execute(
        """
        SELECT COUNT(*) as error_count
        FROM server_logs
        WHERE strftime('%Y-%m-%d', timestamp) = ? AND status_code >= 400;
        """,
        (date,),
    ).fetchall()

    return num_errors


def get_suspicious_ips(db, date):
    rows = db.execute(
        """
        SELECT 
            ip,
            COUNT(*) AS total_requests,
            SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) * 1.0 / COUNT(*) AS error_rate,
            COUNT(DISTINCT path) AS unique_paths
        FROM server_logs
        WHERE strftime('%Y-%m-%d', timestamp) = ?
        GROUP BY ip;
        """,
        (date,),
    ).fetchall()

    ip_data = [dict(row) for row in rows]

    if not ip_data:
        return []

    reqs = [ip["total_requests"] for ip in ip_data]
    errs = [ip["error_rate"] for ip in ip_data]
    paths = [ip["unique_paths"] for ip in ip_data]

    mean_req, stdev_req = statistics.mean(reqs), statistics.stdev(reqs)
    mean_err, stdev_err = statistics.mean(errs), statistics.stdev(errs)
    mean_paths, stdev_paths = statistics.mean(paths), statistics.stdev(paths)

    # Flag IPs above 2 standard deviations in any category
    suspicious = [
        ip
        for ip in ip_data
        if (
            ip["total_requests"] > mean_req + 2 * stdev_req
            or ip["error_rate"] > mean_err + 2 * stdev_err
            or ip["unique_paths"] > mean_paths + 2 * stdev_paths
        )
    ]

    return suspicious


def get_status_code_bar_data_overall(db: Connection, date: str):
    statusCode5XX = db.execute(
        """
        SELECT COUNT(*) as count
        FROM server_logs
        WHERE status_code >= 500 and status_code < 600         
        """,
    ).fetchone()[0]

    statusCode4XX = db.execute(
        """
        SELECT COUNT(*) as count
        FROM server_logs
        WHERE status_code >= 400 and status_code < 500           
        """,
    ).fetchone()[0]

    statusCode3XX = db.execute(
        """
        SELECT COUNT(*) as count
        FROM server_logs
        WHERE status_code >= 300 and status_code < 400        
        """,
    ).fetchone()[0]

    statusCode2XX = db.execute(
        """
        SELECT COUNT(*) as count
        FROM server_logs
        WHERE status_code >= 200 and status_code < 300         
        """,
    ).fetchone()[0]

    data = {
        "2xx": int(statusCode2XX) or 0,
        "3xx": int(statusCode3XX) or 0,
        "4xx": int(statusCode4XX) or 0,
        "5xx": int(statusCode5XX) or 0,
    }

    return data


def get_total_logs_overall(db: Connection, date: str | None = "2025-05-18"):
    total_logs_object = db.execute(
        """
        SELECT COUNT(*) AS total_logs
        FROM server_logs"""
    ).fetchone()

    return total_logs_object["total_logs"]


def get_noisy_ips(db: Connection, date: str):
    noisy_ips = db.execute(
        """
        SELECT ip, COUNT(*) as count
        FROM server_logs
        WHERE strftime('%Y-%m-%d', timestamp) = ?
        GROUP BY ip
        ORDER BY count DESC
        LIMIT 5
        """,
        (date,),
    ).fetchall()

    # Convert to a list of dicts
    result = [{"ip": row["ip"], "count": row["count"]} for row in noisy_ips]
    return result


def get_error_rates(db: Connection, date: str):
    num_errors = db.execute(
        """
        SELECT COUNT(*) as error_count, strftime('%H', timestamp) as hour
        FROM server_logs
        WHERE strftime('%Y-%m-%d', timestamp) = ? AND status_code >= 400
        GROUP BY hour;
        """,
        (date,),
    ).fetchall()

    errors = {"counts": [0 for _ in range(24)]}
    for error in num_errors:
        hour_str = error["hour"]
        errors["counts"][int(hour_str)] = error["error_count"]

    return errors
