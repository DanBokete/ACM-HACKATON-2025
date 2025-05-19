import sqlite3

import geoip2.database
import requests

conn = sqlite3.connect("app.db")

ans = conn.execute(
    """
    SELECT ip, COUNT(*) as request_count
FROM server_logs
WHERE timestamp >= datetime('now', '-10 minutes')
GROUP BY ip
HAVING request_count > 100; 
    """
).fetchall()

# for data in ans:
#     print(data)


def get_address(ip: str):
    reader = geoip2.database.Reader("GeoLite2-Country.mmdb")
    response = reader.country(ip)

    result = {
        "id": response.country.iso_code,
        "name": response.country.name,
    }
    return result


get_address("20.171.207.17")


def get_visual_map_data():
    db = conn

    ips_counter = {}

    ips = db.execute(
        """
        SELECT DISTINCT ip
        FROM server_logs
        WHERE strftime('%Y-%m-%d', timestamp) = '2025-04-17';
        """
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
    print(formatted_output)


conn.close()
