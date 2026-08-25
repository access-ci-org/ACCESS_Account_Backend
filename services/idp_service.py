import xml.etree.ElementTree as ET

import httpx
from botocore.model import defaultdict

from models import IdP

MDQ_IDPS_ALL_URL = "https://mdq.incommon.org/entities/idps/all"

NS = {
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "mdui": "urn:oasis:names:tc:SAML:metadata:ui",
    "mdattr": "urn:oasis:names:tc:SAML:metadata:attribute",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "shibmd": "urn:mace:shibboleth:metadata:1.0",
    "xml": "http://www.w3.org/XML/1998/namespace",
}

ENTITY_CATEGORY_ATTR = "http://macedir.org/entity-category"
HIDE_FROM_DISCOVERY = "http://refeds.org/category/hide-from-discovery"


def best_display_name(entity: ET.Element, entity_id: str) -> str:
    """
    Prefer mdui:DisplayName (in english), else OrganizationDisplayName, else fall back to EntityID.
    """
    # mdui:DisplayName
    display_names = entity.findall(".//mdui:DisplayName", NS)
    if display_names:
        # Prefer English
        for dn in display_names:
            if (
                dn.attrib.get(f"{{{NS['xml']}}}lang") == "en"
                and (dn.text or "").strip()
            ):
                return (dn.text or "").strip()
        # Otherwise first non-empty
        for dn in display_names:
            if (dn.text or "").strip():
                return (dn.text or "").strip()

    # OrganizationDisplayName
    org_dn = entity.find(".//md:OrganizationDisplayName", NS)
    if org_dn is not None and (org_dn.text or "").strip():
        return (org_dn.text or "").strip()

    return entity_id


def is_hidden_from_discovery(entity: ET.Element) -> bool:
    """
    True if the entity carries the REFEDS "hide-from-discovery" entity category,
    which asks discovery services not to list it.
    """
    for attr in entity.findall(".//mdattr:EntityAttributes/saml:Attribute", NS):
        if attr.attrib.get("Name") != ENTITY_CATEGORY_ATTR:
            continue
        for value in attr.findall("saml:AttributeValue", NS):
            if (value.text or "").strip() == HIDE_FROM_DISCOVERY:
                return True

    return False


async def build_idp_domain_mapping() -> dict[str, list[IdP]]:
    """
    Fetch the InCommon MDQ IdP metadata bundle and build a mapping:
      scope_domain -> [IdP(display_name=..., entity_id=...), ...]

    Keys come from shibmd: Scope values. IdPs tagged with the REFEDS
    hide-from-discovery entity category are excluded.
    """

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(MDQ_IDPS_ALL_URL)
        resp.raise_for_status()
        xml_text = resp.text

    root = ET.fromstring(xml_text)

    # The feed typically contains md:EntityDescriptor nodes under a root
    domain_mapping: dict[str, list[IdP]] = defaultdict(list)

    for entity in root.findall(".//md:EntityDescriptor", NS):
        entity_id = entity.attrib.get("entityID")
        if not entity_id:
            continue

        # Respect the IdP's request to stay out of discovery interfaces
        if is_hidden_from_discovery(entity):
            continue

        display_name = best_display_name(entity, entity_id)

        # Find shibmd:Scope elements
        for scope_el in entity.findall(".//shibmd:Scope", NS):
            scope = (scope_el.text or "").strip().lower()
            if not scope:
                continue

            # Store domain - > IdP info
            domain_mapping[scope].append(
                IdP(display_name=display_name, entity_id=entity_id)
            )

    return dict(domain_mapping)
