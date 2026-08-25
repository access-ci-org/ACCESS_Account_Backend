"""Unit tests for the pure XML helpers in services.idp_service."""

import xml.etree.ElementTree as ET

from models import IdP
from services.idp_service import (
    MDQ_IDPS_ALL_URL,
    best_display_name,
    build_idp_domain_mapping,
    is_hidden_from_discovery,
)

ENTITY_ID = "https://idp.example.org/idp"


def _entity(inner: str) -> ET.Element:
    xml = f"""
    <md:EntityDescriptor
        xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
        xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui"
        xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        entityID="{ENTITY_ID}">
      {inner}
    </md:EntityDescriptor>
    """
    return ET.fromstring(xml)


def _entity_attributes(attributes: str) -> str:
    return f"""
    <md:Extensions>
      <mdattr:EntityAttributes>
        {attributes}
      </mdattr:EntityAttributes>
    </md:Extensions>
    """


def _entity_category(*values: str) -> str:
    value_els = "\n".join(
        f"<saml:AttributeValue>{v}</saml:AttributeValue>" for v in values
    )
    return _entity_attributes(
        f"""
        <saml:Attribute
            Name="http://macedir.org/entity-category"
            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
          {value_els}
        </saml:Attribute>
        """
    )


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


def test_hidden_when_hide_from_discovery_category_present():
    entity = _entity(_entity_category("http://refeds.org/category/hide-from-discovery"))
    assert is_hidden_from_discovery(entity) is True


def test_hidden_when_hide_from_discovery_is_one_of_several_categories():
    entity = _entity(
        _entity_category(
            "http://refeds.org/category/research-and-scholarship",
            "http://refeds.org/category/hide-from-discovery",
        )
    )
    assert is_hidden_from_discovery(entity) is True


def test_not_hidden_without_entity_attributes():
    entity = _entity("<md:IDPSSODescriptor></md:IDPSSODescriptor>")
    assert is_hidden_from_discovery(entity) is False


def test_not_hidden_with_other_entity_categories():
    entity = _entity(
        _entity_category("http://refeds.org/category/research-and-scholarship")
    )
    assert is_hidden_from_discovery(entity) is False


def test_not_hidden_when_hide_value_belongs_to_a_different_attribute():
    """The value only counts under the entity-category attribute."""
    entity = _entity(
        _entity_attributes(
            """
            <saml:Attribute Name="http://macedir.org/entity-category-support">
              <saml:AttributeValue>http://refeds.org/category/hide-from-discovery</saml:AttributeValue>
            </saml:Attribute>
            """
        )
    )
    assert is_hidden_from_discovery(entity) is False


FEED = """<?xml version="1.0"?>
<md:EntitiesDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui"
    xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    xmlns:shibmd="urn:mace:shibboleth:metadata:1.0">
  <md:EntityDescriptor entityID="https://visible.example.org/idp">
    <md:IDPSSODescriptor>
      <md:Extensions>
        <shibmd:Scope regexp="false">visible.example.org</shibmd:Scope>
        <mdui:UIInfo>
          <mdui:DisplayName xml:lang="en">Visible University</mdui:DisplayName>
        </mdui:UIInfo>
      </md:Extensions>
    </md:IDPSSODescriptor>
  </md:EntityDescriptor>
  <md:EntityDescriptor entityID="https://hidden.example.org/idp">
    <md:Extensions>
      <mdattr:EntityAttributes>
        <saml:Attribute Name="http://macedir.org/entity-category"
                        NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
          <saml:AttributeValue>http://refeds.org/category/hide-from-discovery</saml:AttributeValue>
        </saml:Attribute>
      </mdattr:EntityAttributes>
    </md:Extensions>
    <md:IDPSSODescriptor>
      <md:Extensions>
        <shibmd:Scope regexp="false">hidden.example.org</shibmd:Scope>
        <mdui:UIInfo>
          <mdui:DisplayName xml:lang="en">Hidden University</mdui:DisplayName>
        </mdui:UIInfo>
      </md:Extensions>
    </md:IDPSSODescriptor>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>
"""


async def test_build_idp_domain_mapping_excludes_hidden_idps(respx_mock):
    respx_mock.get(MDQ_IDPS_ALL_URL).respond(
        200, text=FEED, headers={"Content-Type": "application/samlmetadata+xml"}
    )

    mapping = await build_idp_domain_mapping()

    assert set(mapping) == {"visible.example.org"}
    assert mapping["visible.example.org"] == [
        IdP(
            display_name="Visible University",
            entity_id="https://visible.example.org/idp",
        )
    ]
