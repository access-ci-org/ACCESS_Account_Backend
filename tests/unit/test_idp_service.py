"""Unit tests for services.idp_service.best_display_name (pure XML helper)."""

import xml.etree.ElementTree as ET

from services.idp_service import best_display_name

ENTITY_ID = "https://idp.example.org/idp"


def _entity(inner: str) -> ET.Element:
    xml = f"""
    <md:EntityDescriptor
        xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
        xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui"
        entityID="{ENTITY_ID}">
      {inner}
    </md:EntityDescriptor>
    """
    return ET.fromstring(xml)


def test_prefers_english_display_name():
    entity = _entity(
        """
        <md:IDPSSODescriptor><md:Extensions><mdui:UIInfo>
          <mdui:DisplayName xml:lang="fr">Universite Exemple</mdui:DisplayName>
          <mdui:DisplayName xml:lang="en">Example University</mdui:DisplayName>
        </mdui:UIInfo></md:Extensions></md:IDPSSODescriptor>
        """
    )
    assert best_display_name(entity, ENTITY_ID) == "Example University"


def test_falls_back_to_first_non_empty_display_name_when_no_english():
    entity = _entity(
        """
        <md:IDPSSODescriptor><md:Extensions><mdui:UIInfo>
          <mdui:DisplayName xml:lang="fr">Universite Exemple</mdui:DisplayName>
        </mdui:UIInfo></md:Extensions></md:IDPSSODescriptor>
        """
    )
    assert best_display_name(entity, ENTITY_ID) == "Universite Exemple"


def test_falls_back_to_organization_display_name():
    entity = _entity(
        """
        <md:Organization>
          <md:OrganizationDisplayName xml:lang="en">Example Org</md:OrganizationDisplayName>
        </md:Organization>
        """
    )
    assert best_display_name(entity, ENTITY_ID) == "Example Org"


def test_falls_back_to_entity_id_when_no_names():
    entity = _entity("<md:IDPSSODescriptor></md:IDPSSODescriptor>")
    assert best_display_name(entity, ENTITY_ID) == ENTITY_ID


def test_ignores_blank_display_name():
    entity = _entity(
        """
        <md:IDPSSODescriptor><md:Extensions><mdui:UIInfo>
          <mdui:DisplayName xml:lang="en">   </mdui:DisplayName>
        </mdui:UIInfo></md:Extensions></md:IDPSSODescriptor>
        <md:Organization>
          <md:OrganizationDisplayName xml:lang="en">Fallback Org</md:OrganizationDisplayName>
        </md:Organization>
        """
    )
    assert best_display_name(entity, ENTITY_ID) == "Fallback Org"
