"""
Annotation Builder Module

Creates iCONECT-compatible annotation objects from PII detection results.
Handles Thrift serialization to JSON format for ANNOTS_5 database insertion.

This module builds the complex nested JSON structure required by iCONECT's
annotation system, following the Thrift schema defined in Annotations.thrift.
"""

import sys
import os
from datetime import datetime
from typing import List, Tuple, Optional

# Add gen-py to path for Thrift imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'gen-py'))

from Annotations.ttypes import (
    Annotation,
    AnnotationData,
    enAnnotationType,
    enAnnotationSource
)
from thrift.transport import TTransport
from thrift.protocol import TJSONProtocol


class PII_AnnotationBuilder:
    """
    Builder class for creating PII redaction annotations in iCONECT format.
    """

    # Entity type mappings (customize as needed)
    # TODO: Should probably load these from a config file instead of hardcoding
    # Different document types might need different entity mappings
    ENTITY_TYPE_MAP = {
        "SSN": "SSN",
        "SOCIAL_SECURITY_NUMBER": "SSN",
        "PHONE": "PHONE",
        "PHONE_NUMBER": "PHONE",
        "EMAIL": "EMAIL",
        "EMAIL_ADDRESS": "EMAIL",
        "NAME": "NAME",
        "PERSON": "NAME",
        "ADDRESS": "ADDRESS",
        "LOCATION": "ADDRESS",
        "DATE_OF_BIRTH": "DOB",
        "DOB": "DOB",
        "CREDIT_CARD": "CREDIT_CARD",
        "BANK_ACCOUNT": "BANK_ACCOUNT",
        "DRIVERS_LICENSE": "DRIVERS_LICENSE",
        "PASSPORT": "PASSPORT",
    }

    def __init__(self, creator_name: str = "pii_detector"):
        """
        Initialize the annotation builder.

        Args:
            creator_name: Name to use for sCreatedBy field (e.g., "pii_detector", "ml_engine")
        """
        self.creator_name = creator_name

    def normalize_entity_type(self, entity_type: str) -> str:
        """
        Normalize entity type to standard format.

        Args:
            entity_type: Raw entity type from PII detector

        Returns:
            Normalized entity type string
        """
        entity_type_upper = entity_type.upper().replace(" ", "_")
        return self.ENTITY_TYPE_MAP.get(entity_type_upper, entity_type_upper)

    def create_pii_annotation(
        self,
        entity_type: str,
        entity_value: str,
        normalized_coords: Tuple[float, float, float, float],
        confidence: int,
        page_level_id: int,
        order: Optional[int] = None,
        mask_value: bool = True
    ) -> Annotation:
        """
        Create a single PII redaction annotation.

        Args:
            entity_type: Type of PII (e.g., "SSN", "Name", "Email")
            entity_value: The actual PII value found
            normalized_coords: Tuple of (left, top, width, height) as percentages (0.0-1.0)
            confidence: Confidence score (0-100)
            page_level_id: Unique ID for this annotation on the page
            order: Navigation order (defaults to page_level_id if not provided)
            mask_value: If True, mask the value as "***TYPE***" (e.g., "***SSN***")

        Returns:
            Annotation object ready for serialization
        """
        left, top, width, height = normalized_coords

        # Normalize entity type
        normalized_type = self.normalize_entity_type(entity_type)

        # Mask value if requested
        if mask_value:
            found_value = f"***{normalized_type}***"
        else:
            found_value = entity_value

        # Use page_level_id as order if not specified
        if order is None:
            order = page_level_id

        # Current timestamp in ISO 8601 format
        timestamp = datetime.utcnow().isoformat()

        # Create annotation object
        annotation = Annotation(
            eType=enAnnotationType.annotRedaction,  # Type 2 = redaction
            dXPos=left,                             # X position (0.0-1.0)
            dYPos=top,                              # Y position (0.0-1.0)
            dWidth=width,                           # Width (0.0-1.0)
            dHeight=height,                         # Height (0.0-1.0)
            sFillColour="#000000",                  # Black fill
            sLineColour="#000000",                  # Black outline
            dFillOpacity=1.0,                       # Fully opaque (CRITICAL!)
            dLineOpacity=1.0,                       # Fully opaque outline
            sReasonCategory=normalized_type,        # PII type (field 50)
            sFoundValue=found_value,                # Found value or masked (field 51)
            sCreatedBy=self.creator_name,           # Creator name (field 17)
            sTimeCreated=timestamp,                 # Created timestamp (field 18)
            sModifiedBy=self.creator_name,          # Modified by (field 19)
            sModifiedTime=timestamp,                # Modified timestamp (field 20)
            eSource=enAnnotationSource.massActionCreated,  # Source = batch (field 54)
            iPageLevelID=page_level_id,             # Unique per page (field 21)
            iOrder=order,                           # Navigation order (field 12)
            iConfidence=confidence                  # Confidence score (field 53)
        )

        return annotation

    def create_annotation_data(
        self,
        annotations: List[Annotation],
        page_number: int
    ) -> AnnotationData:
        """
        Create AnnotationData object for a single page.

        Args:
            annotations: List of Annotation objects for this page
            page_number: Page number (0-based)

        Returns:
            AnnotationData object ready for serialization
        """
        return AnnotationData(
            aAnnots=annotations,                    # List of annotations (field 1)
            iPageLevelIDCount=len(annotations),     # Count of annotations (field 2)
            lPageNumber=page_number                 # Page number (field 5)
        )

    def serialize_to_json(self, annot_data: AnnotationData) -> str:
        """
        Serialize AnnotationData to Thrift JSON format.

        Args:
            annot_data: AnnotationData object to serialize

        Returns:
            JSON string in Thrift format, ready for ANNOT_DATA column
        """
        transport = TTransport.TMemoryBuffer()
        protocol = TJSONProtocol.TJSONProtocol(transport)
        annot_data.write(protocol)
        return transport.getvalue().decode('utf-8')

    def deserialize_from_json(self, json_str: str) -> AnnotationData:
        """
        Deserialize Thrift JSON back to AnnotationData object.

        Args:
            json_str: JSON string in Thrift format

        Returns:
            AnnotationData object
        """
        transport = TTransport.TMemoryBuffer(json_str.encode('utf-8'))
        protocol = TJSONProtocol.TJSONProtocol(transport)
        annot_data = AnnotationData()
        annot_data.read(protocol)
        return annot_data

    def build_from_pii_detections(
        self,
        pii_detections: List[dict],
        page_number: int
    ) -> Tuple[AnnotationData, str]:
        """
        Build complete AnnotationData from PII detection results.

        Args:
            pii_detections: List of dictionaries with keys:
                - type: Entity type (e.g., "SSN", "Name")
                - value: Entity value
                - normalized_coords: Tuple (left, top, width, height)
                - confidence: Confidence score (0-100)
            page_number: Page number (0-based)

        Returns:
            Tuple of (AnnotationData object, JSON string)

        Example:
            pii_detections = [
                {
                    "type": "SSN",
                    "value": "123-45-6789",
                    "normalized_coords": (0.15, 0.25, 0.10, 0.02),
                    "confidence": 98
                },
                {
                    "type": "Name",
                    "value": "John Doe",
                    "normalized_coords": (0.20, 0.35, 0.08, 0.015),
                    "confidence": 95
                }
            ]
        """
        annotations = []

        for i, pii in enumerate(pii_detections, start=1):
            annotation = self.create_pii_annotation(
                entity_type=pii.get("type", "UNKNOWN"),
                entity_value=pii.get("value", ""),
                normalized_coords=pii.get("normalized_coords"),
                confidence=pii.get("confidence", 0),
                page_level_id=i,
                order=i
            )
            annotations.append(annotation)

        # Create AnnotationData
        annot_data = self.create_annotation_data(annotations, page_number)

        # Serialize to JSON
        json_str = self.serialize_to_json(annot_data)

        return annot_data, json_str


def format_for_database_insertion(
    json_blob: str,
    object_id: int,
    field_id: int,
    set_id: int,
    document_filename: str,
    document_hash: str,
    page_number: int
) -> dict:
    """
    Format annotation data for database insertion into ANNOTS_5.

    Args:
        json_blob: Serialized JSON from serialize_to_json()
        object_id: Document ID (OBJECT_ID)
        field_id: Field ID (typically 382 for redactions)
        set_id: Set ID (typically 1)
        document_filename: PDF filename
        document_hash: MD5/SHA hash of document
        page_number: Page number (0-based for LOOKUP_INFO2)

    Returns:
        Dictionary with fields ready for SQL INSERT
    """
    return {
        "OBJECT_ID": object_id,
        "FIELD_ID": field_id,
        "SET_ID": set_id,
        "LOOKUP_INFO1": f"{document_filename}:{document_hash}",
        "LOOKUP_INFO2": str(page_number),
        "ANNOT_DATA": json_blob,
        "UPDATED": datetime.utcnow().isoformat()
    }


if __name__ == "__main__":
    # Example usage and testing
    print("Annotation Builder Test")
    print("=" * 60)

    # Create builder
    builder = PII_AnnotationBuilder(creator_name="pii_detector_test")

    # Test case 1: Single annotation
    print("\nTest 1: Create single SSN annotation")
    annotation = builder.create_pii_annotation(
        entity_type="SSN",
        entity_value="123-45-6789",
        normalized_coords=(0.15, 0.25, 0.10, 0.02),
        confidence=98,
        page_level_id=1
    )
    print(f"  Created annotation: {annotation}")
    print(f"  Type: {annotation.eType}")
    print(f"  Position: ({annotation.dXPos:.4f}, {annotation.dYPos:.4f})")
    print(f"  Size: {annotation.dWidth:.4f} x {annotation.dHeight:.4f}")
    print(f"  Reason: {annotation.sReasonCategory}")
    print(f"  Found: {annotation.sFoundValue}")

    # Test case 2: Multiple annotations
    print("\nTest 2: Create multiple PII annotations")
    pii_detections = [
        {
            "type": "SSN",
            "value": "123-45-6789",
            "normalized_coords": (0.15, 0.25, 0.10, 0.02),
            "confidence": 98
        },
        {
            "type": "PHONE",
            "value": "555-1234",
            "normalized_coords": (0.20, 0.35, 0.08, 0.015),
            "confidence": 95
        },
        {
            "type": "EMAIL",
            "value": "test@example.com",
            "normalized_coords": (0.30, 0.45, 0.12, 0.02),
            "confidence": 92
        }
    ]

    annot_data, json_blob = builder.build_from_pii_detections(pii_detections, page_number=0)

    print(f"  Created {len(annot_data.aAnnots)} annotations")
    print(f"  Page number: {annot_data.lPageNumber}")
    print(f"  Page level ID count: {annot_data.iPageLevelIDCount}")

    # Test case 3: Serialize to JSON
    print("\nTest 3: Serialize to JSON")
    print(f"  JSON length: {len(json_blob)} characters")
    print(f"  First 200 chars: {json_blob[:200]}...")

    # Test case 4: Round-trip (serialize and deserialize)
    print("\nTest 4: Round-trip test")
    deserialized = builder.deserialize_from_json(json_blob)
    print(f"  Deserialized {len(deserialized.aAnnots)} annotations")
    print(f"  Page number matches: {deserialized.lPageNumber == annot_data.lPageNumber}")
    print(f"  First annotation type: {deserialized.aAnnots[0].sReasonCategory}")

    # Test case 5: Database format
    print("\nTest 5: Format for database insertion")
    db_record = format_for_database_insertion(
        json_blob=json_blob,
        object_id=16709,
        field_id=382,
        set_id=-1,
        document_filename="test_invoice.pdf",
        document_hash="abc123def456",
        page_number=0
    )
    print("  Database record fields:")
    for key, value in db_record.items():
        if key == "ANNOT_DATA":
            print(f"    {key}: <{len(value)} chars>")
        else:
            print(f"    {key}: {value}")

    print("\n" + "=" * 60)
    print("All tests completed!")
