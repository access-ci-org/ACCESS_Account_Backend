import xml.etree.ElementTree as ET
import httpx

MDQ_IDPS_ALL_URL = "https://mdq.incommon.org/entities/idps/all"

NS = {
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "mdui": "urn:oasis:names:tc:SAML:metadata:ui",
    "shibmd": "urn:mace:shibboleth:metadata:1.0",
    "xml": "http://www.w3.org/XML/1998/namespace",
}


def best_display_name(entity: ET.Element, entity_id: str) -> str:
    """
    Prefer mdui:DisplayName (in english), else OrganizationDisplayName, else fall back to EntityID.
    """
    # mdui:DisplayName
    display_names = entity.findall(".//mdui:DisplayName", NS)
    if display_names:
        # Prefer English
        for dn in display_names:
            if dn.attrib.get(f"{{{NS['xml']}}}lang") == "en" and (dn.text or "").strip():
                return dn.text.strip()
        # Otherwise first non-empty
        for dn in display_names:
            if (dn.text or "").strip():
                return dn.text.strip()
            
    
    # OrganizationDisplayName
    org_dn = entity.find(".//md:OrganizationDisplayName", NS)
    if org_dn is not None and (org_dn.text or "").strip():
        return org_dn.text.strip()
    
    return entity_id

async def build_idp_domain_mapping() -> dict[str, dict[str, str]]:
    """
    Fetch the InCommon MDQ IdP metadata bundle and build a mapping:
      scope_domain -> {"display_name": ..., "entity_id": ...} 

    Keys come from shibmd: Scope values.
    """

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(MDQ_IDPS_ALL_URL)
        resp.raise_for_status()
        xml_text = resp.text
    
    root = ET.fromstring(xml_text)

    # The feed typically contains md:EntityDescriptor nodes under a root
    domain_mapping: dict[str, dict[str, str]] = {}

    for entity in root.findall(".//md:EntityDescriptor", NS):
        entity_id = entity.attrib.get("entityID")
        if not entity_id:
            continue

        display_name = best_display_name(entity, entity_id)

        # Find shibmd:Scope elements
        for scope_el in entity.findall(".//shibmd:Scope", NS):
            scope = (scope_el.text or "").strip().lower()
            if not scope:
                continue

            # Store domain - > IdP info
            domain_mapping[scope] = {
                "display_name": display_name,
                "entity_id": entity_id,
            }
    
    return domain_mapping

