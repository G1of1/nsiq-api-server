def validate_domain(domain: str):
    from src.services.security import validate_public_target
    try:
        host, addresses = validate_public_target(domain)
        return {"result": {"valid": True, "domain": host, "resolved_addresses": addresses}}
    except ValueError as exc:
        return {"error": str(exc)}
