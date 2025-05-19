import io
import re
import textwrap
from flask import (
    Flask,
    request,
    send_file,
    render_template,
)
from database import close_db, get_db
from flask_session import Session

# from query import get_average_rating
from flask_session import Session

from map import get_address
from models import (
    get_error_rates,
    get_ip_comparison,
    get_max_date,
    get_noisy_ips,
    get_status_code,
    get_status_code_bar_data,
    get_status_code_bar_data_overall,
    get_suspicious_ips,
    get_total_logs,
    get_total_logs_overall,
    get_traffic_for_day,
    get_avg_response_size,
    get_top_endPoints,
    get_traffic_spikes,
    get_visual_map_data,
)

app = Flask(__name__)
app.teardown_appcontext(close_db)
app.config["SESSION_PERMANENT"] = False
app.config["SECRET_KEY"] = (
    "50e5c6e09a9e67f98a25da2c2f32fe01aa47b28779a9a83874c8b75e3decbaee"
)
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


log_pattern = log_pattern = re.compile(
    r"(?P<ip>\S+) \S+ \S+ "
    r"\[(?P<date>[^\]]+)\] "
    r'"(?P<method>\S+) (?P<url>\S+) \S+" '
    r"(?P<status>\d{3}) (?P<size>\d+|-) "
    r'"(?P<referrer>[^"]*)" '
    r'"(?P<user_agent>[^"]*)"'
)


def parse_log_line(line):
    match = log_pattern.match(line)
    return match.groupdict() if match else None


# @app.route("/")
# def populate_db():
#     with open("access.log") as f:
#         db = get_db()
#         for row in f:
#             parsed = parse_log_line(row)
#             if not parsed:
#                 continue

#             raw_timestamp = parsed["date"]
#             dt = datetime.strptime(raw_timestamp, "%d/%b/%Y:%H:%M:%S %z")
#             normalized_date = dt.strftime("%Y-%m-%d %H:%M:%S")

#             db.execute(
#                 """INSERT INTO server_logs (ip, timestamp, http_method, path, status_code, size, referrer, user_agent)
#                         VALUES (?,?,?,?,?,?,?,?);""",
#                 (
#                     parsed["ip"],
#                     normalized_date,
#                     parsed["method"],
#                     parsed["url"],
#                     parsed["status"],
#                     parsed["size"],
#                     parsed["referrer"],
#                     parsed["user_agent"],
#                 ),
#             )

#             db.commit()

#         close_db()
#         return ""


@app.route("/dashboard")
def dashboard():
    db = get_db()
    # date = get_max_date(db)
    date = request.args.get("date") or get_max_date(db)
    number_of_ips = get_ip_comparison(db, date)
    total_logs = get_total_logs(db, date)
    status_codes = get_status_code(db, date)
    geographic_data = get_visual_map_data(db, date)
    status_codes_bar_data = get_status_code_bar_data(db, date)
    traffic_for_day = get_traffic_for_day(db, date)
    avg_response_size = get_avg_response_size(db, date)
    top_endpoints = get_top_endPoints(db, date)
    ip_comparison = get_ip_comparison(db, date)
    suspicious_ips = get_suspicious_ips(db, date)
    noisy_ip = get_noisy_ips(db, date)
    error_rates = get_error_rates(db, date)
    traffic_spikes = get_traffic_spikes(db, date)

    print(suspicious_ips)

    # return jsonify(num)
    return render_template(
        "index.html",
        number_of_ips=number_of_ips,
        total_logs=total_logs,
        status_codes=status_codes,
        geographic_data=geographic_data,
        status_codes_bar_data=status_codes_bar_data,
        traffic_for_day=traffic_for_day,
        avg_response_size=avg_response_size,
        top_endpoints=top_endpoints,
        date=date,
        ip_comparison=ip_comparison,
        suspicious_ips=suspicious_ips,
        noisy_ip=noisy_ip,
        error_rates=error_rates,
        traffic_spikes=traffic_spikes,
    )


# @app.route("/routes")
# def get_visual_map_data():
#     db = get_db()

#     ips_counter = {}

#     ips = db.execute(
#         """
#         SELECT DISTINCT ip
#         FROM server_logs
#         WHERE strftime('%Y-%m-%d', timestamp) = '2025-04-17';
#         """
#     ).fetchall()

#     ip_list = [ip_tuple[0] for ip_tuple in ips]

#     for ip in ip_list:

#         location_data = get_address(str(ip))
#         key = (location_data["id"], location_data["name"])

#         if key in ips_counter:
#             ips_counter[key] += 1
#         else:
#             ips_counter[key] = 1

#     formatted_output = []

#     for country in ips_counter:
#         formatted_output.append(
#             {"id": country[0], "name": country[1], "value": ips_counter[country]}
#         )
#     return formatted_output


# get_visual_map_data()

# def region_status_anomalies():


@app.route("/logs")
def logs():

    db = get_db()

    # get all logs

    logs = db.execute(
        """SELECT http_method, ip, strftime("%Y-%m-%d %H:%M:%S", timestamp) as time, 
                      status_code, user_agent, path
                      FROM server_logs
                      LIMIT 4000
                      """
    ).fetchall()

    log_list = [dict(log) for log in logs]

    return render_template("logs.html", log_list=log_list)


@app.route("/ip/<ip_address>")
def show_ip_info(ip_address):

    risk_list = []
    db = get_db()

    # Get IP info (arbitrary info from a sample request on that day)
    date = request.args.get("date") or get_max_date(db)
    status_codes = get_status_code(db, date)
    ip_info = db.execute(
        """
        SELECT
        ip,
        COUNT(*) AS request_count,
        COUNT(DISTINCT path) AS unique_paths,
        COUNT(DISTINCT user_agent) AS user_agents_used,
        SUM(size) AS total_data_transferred,
        MIN(timestamp) AS first_seen,
        MAX(timestamp) AS last_seen
        FROM
        server_logs
        WHERE
        DATE(timestamp) = ?
        GROUP BY
        ip
        ORDER BY
        request_count DESC;
    """,
        (date,),
    ).fetchone()

    if ip_info is not None:
        ip_info = dict(ip_info)

    # Check for high request volume
    num_requests = db.execute(
        """
        SELECT COUNT(*) FROM server_logs
        WHERE ip = ? AND date(timestamp) = ?
    """,
        (ip_address, date),
    ).fetchone()

    print(dict(num_requests))

    if num_requests and num_requests[0] > 200:
        risk_list.append("High request volume detected.")

    # Repetitive access to same path
    repetitive_access = db.execute(
        """
        SELECT path, COUNT(*) FROM server_logs
        WHERE ip = ? AND date(timestamp) = ?
        GROUP BY path
        HAVING COUNT(*) > 20
    """,
        (ip_address, date),
    ).fetchall()

    if repetitive_access and len(repetitive_access) > 0:
        risk_list.append("Repetitive access patterns detected.")

    # High number of failed requests (4xx or 5xx)
    fail_requests = db.execute(
        """
        SELECT COUNT(*) FROM server_logs
        WHERE ip = ? AND status_code >= 400 AND date(timestamp) = ?
    """,
        (ip_address, date),
    ).fetchone()

    temp_db_data = db.execute(
        """
        WITH hours AS (
        SELECT 0 AS hour UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3
        UNION ALL SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7
        UNION ALL SELECT 8 UNION ALL SELECT 9 UNION ALL SELECT 10 UNION ALL SELECT 11
        UNION ALL SELECT 12 UNION ALL SELECT 13 UNION ALL SELECT 14 UNION ALL SELECT 15
        UNION ALL SELECT 16 UNION ALL SELECT 17 UNION ALL SELECT 18 UNION ALL SELECT 19
        UNION ALL SELECT 20 UNION ALL SELECT 21 UNION ALL SELECT 22 UNION ALL SELECT 23
        ),
        hourly_counts AS (
        SELECT
            CAST(strftime('%H', timestamp) AS INTEGER) AS hour,
            status_code
        FROM
            server_logs
        WHERE
            DATE(timestamp) = ? AND
            ip = ?
        )
        SELECT
        printf('%02d:00', h.hour) AS hour_label,
        COALESCE(SUM(CASE WHEN hc.status_code BETWEEN 100 AND 500 THEN 1 ELSE 0 END), 0) AS status,
        COALESCE(SUM(CASE WHEN hc.status_code BETWEEN 200 AND 299 THEN 1 ELSE 0 END), 0) AS status_2xx,
        COALESCE(SUM(CASE WHEN hc.status_code BETWEEN 300 AND 399 THEN 1 ELSE 0 END), 0) AS status_3xx,
        COALESCE(SUM(CASE WHEN hc.status_code BETWEEN 400 AND 499 THEN 1 ELSE 0 END), 0) AS status_4xx,
        COALESCE(SUM(CASE WHEN hc.status_code >= 500 THEN 1 ELSE 0 END), 0) AS status_5xx
        FROM
        hours h
        LEFT JOIN
        hourly_counts hc
        ON
        h.hour = hc.hour
        GROUP BY
        h.hour
        ORDER BY
        h.hour;
        """,
        (
            date,
            ip_address,
        ),
    ).fetchall()

    db_data = []
    five_hundreds = []
    four_hundreds = []
    three_hundreds = []
    two_hundreds = []
    all_hundreds = []

    if temp_db_data:
        for data in temp_db_data:
            data = dict(data)
            five_hundreds.append(data["status_5xx"])
            four_hundreds.append(data["status_4xx"])
            three_hundreds.append(data["status_3xx"])
            two_hundreds.append(data["status_2xx"])
            all_hundreds.append(data["status"])
            db_data.append(data)

    if fail_requests and fail_requests[0] > 10:
        risk_list.append("High number of 4xx/5xx error responses.")

    # Risk score = number of triggered risk rules
    risk_score = len(risk_list)

    country = get_address(ip_address)

    logs = db.execute(
        """
        SELECT * 
        FROM server_logs
        WHERE date(timestamp) = ? AND ip = ?
        """,
        (
            date,
            ip_address,
        ),
    ).fetchall()

    return render_template(
        "ips.html",
        country=country,
        ip=ip_address,
        ip_info=ip_info,
        risk_score=risk_score,
        risk_list=risk_list,
        date=date,
        db_data=db_data,
        five_hundreds=five_hundreds,
        four_hundreds=four_hundreds,
        three_hundreds=three_hundreds,
        two_hundreds=two_hundreds,
        all_hundreds=all_hundreds,
        logs=logs,
        status_codes=status_codes,
    )


@app.route("/download")
def download():

    db = get_db()
    date = request.args.get("date") or get_max_date(db)

    # get start date
    start_date = db.execute(
        """SELECT date(timestamp) as dt FROM server_logs
                            ORDER BY dt ASC
                            LIMIT 1"""
    ).fetchone()

    # get end date
    end_date = db.execute(
        """SELECT date(timestamp) as dt FROM server_logs
                            ORDER BY dt DESC
                            LIMIT 1"""
    ).fetchone()

    start_date = start_date["dt"] if start_date else "N/A"
    end_date = end_date["dt"] if end_date else "N/A"

    # number of logs
    total_logs = get_total_logs_overall(db, date)

    # number of different codes
    code_data = get_status_code_bar_data_overall(db, date)

    # unique ips
    unique_ips = db.execute(
        """SELECT COUNT(DISTINCT ip)
                            FROM server_logs"""
    ).fetchone()[0]

    # highest traffic
    highest_traffic = db.execute(
        """SELECT date(timestamp) as dt, COUNT(*)
                                FROM server_logs
                                GROUP BY dt
                                ORDER BY COUNT(*) ASC
                                LIMIT 1"""
    ).fetchone()

    # lowest traffic
    lowest_traffic = db.execute(
        """SELECT date(timestamp) as dt, COUNT(*)
                                FROM server_logs
                                GROUP BY dt
                                ORDER BY COUNT(*) DESC
                                LIMIT 1"""
    ).fetchone()

    highest_traffic = (
        f"{highest_traffic['dt']} ({highest_traffic['COUNT(*)']} logs)"
        if highest_traffic
        else "N/A"
    )
    lowest_traffic = (
        f"{lowest_traffic['dt']} ({lowest_traffic['COUNT(*)']} logs)"
        if lowest_traffic
        else "N/A"
    )

    # average logs per day
    avg_logs_per_day = db.execute(
        """
        SELECT COUNT(*) * 1.0 / COUNT(DISTINCT date(timestamp)) AS avg
        FROM server_logs
    """
    ).fetchone()["avg"]

    # top IP by request count
    top_ip_data = db.execute(
        """
        SELECT ip, COUNT(*) as count 
        FROM server_logs 
        GROUP BY ip 
        ORDER BY count DESC 
        LIMIT 1
    """
    ).fetchone()
    top_ip = (
        f"{top_ip_data['ip']} ({top_ip_data['count']} requests)"
        if top_ip_data
        else "N/A"
    )

    # most common status code
    common_status = db.execute(
        """
        SELECT status_code, COUNT(*) as count 
        FROM server_logs 
        GROUP BY status_code 
        ORDER BY count DESC 
        LIMIT 1
    """
    ).fetchone()
    most_common_status = (
        f"{common_status['status_code']} ({common_status['count']} times)"
        if common_status
        else "N/A"
    )

    # error rate (4xx + 5xx)
    error_count = code_data["4xx"] + code_data["5xx"]
    error_rate = (error_count) / total_logs * 100 if total_logs > 0 else 0

    log_data = textwrap.dedent(
        f"""
    Log File Statistics
    {start_date} - {end_date}

    Total logs: {total_logs}

    2xx requests: {code_data["2xx"]}
    3xx requests: {code_data["3xx"]}
    4xx requests: {code_data["4xx"]}
    5xx requests: {code_data["5xx"]}

    Unique IPs: {unique_ips}

    Highest traffic (day): {lowest_traffic}
    Lowest traffic (day): {highest_traffic}

    --- Additional Insights ---
    Average requests per day: {avg_logs_per_day:.2f}
    Top IP address: {top_ip}
    Most common status code: {most_common_status}
    Error rate: {error_rate:.2f}%
    
"""
    ).strip()

    buffer = io.BytesIO()
    buffer.write(log_data.encode("utf-8"))
    buffer.seek(0)

    return send_file(buffer, as_attachment=True, download_name="metrics_log.txt")
