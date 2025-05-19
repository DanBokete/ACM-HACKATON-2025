import geoip2.database


def get_address(ip: str):
    reader = geoip2.database.Reader("GeoLite2-Country.mmdb")
    response = reader.country(ip)

    result = {
        "id": response.country.iso_code,
        "name": response.country.name,
    }
    return result
