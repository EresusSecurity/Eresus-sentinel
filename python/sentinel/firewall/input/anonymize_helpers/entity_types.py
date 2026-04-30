"""Entity type definitions for NER-based anonymization."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class EntityType(str, Enum):
    PERSON = "PERSON"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    SSN = "SSN"
    CREDIT_CARD = "CREDIT_CARD"
    IBAN = "IBAN"
    IP_ADDRESS = "IP_ADDRESS"
    URL = "URL"
    DATE_OF_BIRTH = "DATE_OF_BIRTH"
    ADDRESS = "ADDRESS"
    LOCATION = "LOCATION"
    ORGANIZATION = "ORGANIZATION"
    PASSPORT = "PASSPORT"
    DRIVERS_LICENSE = "DRIVERS_LICENSE"
    MEDICAL_RECORD = "MEDICAL_RECORD"
    AWS_KEY = "AWS_KEY"
    API_KEY = "API_KEY"
    PASSWORD = "PASSWORD"
    BANK_ACCOUNT = "BANK_ACCOUNT"
    CRYPTO_WALLET = "CRYPTO_WALLET"
    NATIONAL_ID = "NATIONAL_ID"
    TAX_ID = "TAX_ID"
    VEHICLE_ID = "VEHICLE_ID"
    BIOMETRIC = "BIOMETRIC"
    GENETIC = "GENETIC"


@dataclass
class EntityConfig:
    entity_type: EntityType
    label: str
    category: str
    gdpr_relevant: bool = False
    hipaa_relevant: bool = False
    pci_relevant: bool = False
    replacement_prefix: str = ""

    def __post_init__(self):
        if not self.replacement_prefix:
            self.replacement_prefix = f"[{self.entity_type.value}]"


PII_ENTITIES = {
    EntityType.PERSON, EntityType.EMAIL, EntityType.PHONE, EntityType.SSN,
    EntityType.DATE_OF_BIRTH, EntityType.ADDRESS, EntityType.PASSPORT,
    EntityType.DRIVERS_LICENSE, EntityType.NATIONAL_ID, EntityType.TAX_ID,
    EntityType.BIOMETRIC, EntityType.GENETIC,
}

FINANCIAL_ENTITIES = {
    EntityType.CREDIT_CARD, EntityType.IBAN, EntityType.BANK_ACCOUNT,
    EntityType.CRYPTO_WALLET,
}

HEALTH_ENTITIES = {
    EntityType.MEDICAL_RECORD, EntityType.BIOMETRIC, EntityType.GENETIC,
}

CREDENTIAL_ENTITIES = {
    EntityType.AWS_KEY, EntityType.API_KEY, EntityType.PASSWORD,
}

ENTITY_REGISTRY: dict[EntityType, EntityConfig] = {
    EntityType.PERSON: EntityConfig(EntityType.PERSON, "Person Name", "PII", gdpr_relevant=True, hipaa_relevant=True),
    EntityType.EMAIL: EntityConfig(EntityType.EMAIL, "Email Address", "PII", gdpr_relevant=True),
    EntityType.PHONE: EntityConfig(EntityType.PHONE, "Phone Number", "PII", gdpr_relevant=True),
    EntityType.SSN: EntityConfig(EntityType.SSN, "Social Security Number", "PII", gdpr_relevant=True, hipaa_relevant=True),
    EntityType.CREDIT_CARD: EntityConfig(EntityType.CREDIT_CARD, "Credit Card", "Financial", pci_relevant=True),
    EntityType.IBAN: EntityConfig(EntityType.IBAN, "IBAN", "Financial"),
    EntityType.IP_ADDRESS: EntityConfig(EntityType.IP_ADDRESS, "IP Address", "Technical", gdpr_relevant=True),
    EntityType.URL: EntityConfig(EntityType.URL, "URL", "Technical"),
    EntityType.DATE_OF_BIRTH: EntityConfig(EntityType.DATE_OF_BIRTH, "Date of Birth", "PII", gdpr_relevant=True, hipaa_relevant=True),
    EntityType.ADDRESS: EntityConfig(EntityType.ADDRESS, "Physical Address", "PII", gdpr_relevant=True),
    EntityType.LOCATION: EntityConfig(EntityType.LOCATION, "Location", "PII", gdpr_relevant=True),
    EntityType.ORGANIZATION: EntityConfig(EntityType.ORGANIZATION, "Organization", "PII"),
    EntityType.PASSPORT: EntityConfig(EntityType.PASSPORT, "Passport Number", "PII", gdpr_relevant=True),
    EntityType.DRIVERS_LICENSE: EntityConfig(EntityType.DRIVERS_LICENSE, "Driver's License", "PII", gdpr_relevant=True),
    EntityType.MEDICAL_RECORD: EntityConfig(EntityType.MEDICAL_RECORD, "Medical Record", "Health", hipaa_relevant=True),
    EntityType.AWS_KEY: EntityConfig(EntityType.AWS_KEY, "AWS Access Key", "Credential"),
    EntityType.API_KEY: EntityConfig(EntityType.API_KEY, "API Key", "Credential"),
    EntityType.PASSWORD: EntityConfig(EntityType.PASSWORD, "Password", "Credential"),
    EntityType.BANK_ACCOUNT: EntityConfig(EntityType.BANK_ACCOUNT, "Bank Account", "Financial", pci_relevant=True),
    EntityType.CRYPTO_WALLET: EntityConfig(EntityType.CRYPTO_WALLET, "Crypto Wallet", "Financial"),
    EntityType.NATIONAL_ID: EntityConfig(EntityType.NATIONAL_ID, "National ID", "PII", gdpr_relevant=True),
    EntityType.TAX_ID: EntityConfig(EntityType.TAX_ID, "Tax ID", "PII"),
    EntityType.VEHICLE_ID: EntityConfig(EntityType.VEHICLE_ID, "Vehicle ID", "PII"),
    EntityType.BIOMETRIC: EntityConfig(EntityType.BIOMETRIC, "Biometric Data", "Health", gdpr_relevant=True, hipaa_relevant=True),
    EntityType.GENETIC: EntityConfig(EntityType.GENETIC, "Genetic Data", "Health", gdpr_relevant=True, hipaa_relevant=True),
}


def get_entities_for_compliance(framework: str) -> set[EntityType]:
    framework = framework.upper()
    if framework == "GDPR":
        return {et for et, cfg in ENTITY_REGISTRY.items() if cfg.gdpr_relevant}
    elif framework == "HIPAA":
        return {et for et, cfg in ENTITY_REGISTRY.items() if cfg.hipaa_relevant}
    elif framework == "PCI":
        return {et for et, cfg in ENTITY_REGISTRY.items() if cfg.pci_relevant}
    return set(EntityType)
