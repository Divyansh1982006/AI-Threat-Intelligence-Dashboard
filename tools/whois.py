import whois


def check_domain(domain):

    try:
        data = whois.whois(domain)

        return {
            "status": "success",
            "domain": domain,
            "registrar": data.registrar,
            "creation_date": data.creation_date,
            "expiration_date": data.expiration_date,
            "name_servers": data.name_servers,
            "status_info": data.status
        }

    except Exception as error:
        return {
            "status": "error",
            "message": str(error)
        }