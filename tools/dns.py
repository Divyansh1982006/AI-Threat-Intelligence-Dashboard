import dns.resolver


def check_domain(domain):

    records = {}

    try:
        for record_type in ["A", "AAAA", "MX", "NS", "CNAME", "TXT"]:
            try:
                answers = dns.resolver.resolve(domain, record_type)

                if record_type == "MX":
                    records[record_type] = [
                        str(answer.exchange).rstrip(".")
                        for answer in answers
                    ]

                elif record_type == "TXT":
                    records[record_type] = [
                        " ".join(answer.strings.decode(errors="ignore")
                                 if isinstance(answer.strings, bytes)
                                 else str(answer))
                        for answer in answers
                    ]

                else:
                    records[record_type] = [
                        str(answer)
                        for answer in answers
                    ]

            except (
                dns.resolver.NoAnswer,
                dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers,
                dns.resolver.Timeout
            ):
                records[record_type] = []

        return {
            "status": "success",
            "domain": domain,
            "records": records
        }

    except Exception as error:
        return {
            "status": "error",
            "message": str(error)
        }