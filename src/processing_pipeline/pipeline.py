import os
import tempfile
import hashlib
import logging
import argparse
import re
from typing import Dict, List, Optional, Union, Any, Tuple
from PIL import Image
from pdf2image import convert_from_path

# Local imports
from ocr_pipeline.ocr.ocr import TextExtraction
from classifier.entity_classifier.entity_classifier import EntityClassifier
from coordinate_converter import (
    pixel_bbox_to_normalized,
    validate_normalized_coords
)
from annotation_builder import PII_AnnotationBuilder
from annotation_db_manager import AnnotationDBManager

# Configure logging: write INFO and above to a file and also output to console
logger = logging.getLogger('pipeline')
logger.setLevel(logging.INFO)

# File handler
file_handler = logging.FileHandler('pii_pipeline.log', mode='w')
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))
logger.addHandler(console_handler)

# Suppress logging from entity classifier
logging.getLogger("classifier").setLevel(logging.ERROR)
# logger = logging.getLogger(__name__)  # Removed to keep custom logger with handlers



Box = List[int]  # [x1, y1, x2, y2]


class DocumentProcessor:
    def __init__(self, db_config_path: Optional[str] = None):
        """
        Initialize the DocumentProcessor with necessary components.
        """
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        
        if db_config_path is None:
            db_config_path = os.path.join("db_config.yaml")
        logger.info(f"Using DB config path: {db_config_path}")
        #self.db_manager = AnnotationDBManager(db_config_path)
        self.annotation_builder = PII_AnnotationBuilder(creator_name="pii_pipeline")
        
        # Initialize models
        logger.info("Initializing EntityClassifier...")
        self.entity_classifier = EntityClassifier(countries=["US"])
        
        logger.info("Initializing TextExtraction...")
        self.text_extraction = TextExtraction()

    def resize_for_ocr(self, img: Image.Image, min_size: int = 800, max_size: int = 1600) -> Image.Image:
        """
        Resize image for optimal OCR performance.
        """
        w, h = img.size
        max_dim = max(w, h)

        if max_dim > max_size:
            scale = max_size / max_dim
        elif max_dim < min_size:
            scale = min_size / max_dim
        else:
            return img

        new_w = int(w * scale)
        new_h = int(h * scale)
        return img.resize((new_w, new_h), Image.LANCZOS)

    def find_target_bboxes(
        self,
        target: str,
        ocr_dict: Dict,
        match_case: bool = False,
        return_all: bool = False,
    ) -> Optional[Union[Box, List[Box]]]:
        """
        Find bounding box(es) for a target phrase in PaddleOCR results.
        """
        text_lines = ocr_dict.get("text_word", [])
        box_lines = ocr_dict.get("text_word_boxes", [])

        if not text_lines or not box_lines:
            return [] if return_all else None

        # Flatten tokens with metadata
        flattened_tokens = []
        for line_idx, (line_tokens, line_boxes) in enumerate(zip(text_lines, box_lines)):
            length = min(len(line_tokens), len(line_boxes))
            for token_idx in range(length):
                flattened_tokens.append({
                    "line_idx": line_idx,
                    "token_idx": token_idx,
                    "text": line_tokens[token_idx],
                    "box": line_boxes[token_idx]
                })

        if not flattened_tokens:
            return [] if return_all else None

        def normalize(text: str, is_target: bool = False) -> str:
            text = re.sub(r'\s+', ' ', text)
            text = text.strip()
            if not match_case:
                text = text.lower()
            text = text.strip(",.:;-")
            return text

        normalized_target = normalize(target, is_target=True)
        if not normalized_target:
            return [] if return_all else None

        found_boxes = []
        n_tokens = len(flattened_tokens)

        for i in range(n_tokens):
            if not normalize(flattened_tokens[i]["text"]):
                continue

            current_text = ""
            for j in range(i, n_tokens):
                token_text = flattened_tokens[j]["text"]
                current_text += token_text
                
                normalized_window = normalize(current_text)
                
                if normalized_window == normalized_target:
                    min_x, min_y = float('inf'), float('inf')
                    max_x, max_y = float('-inf'), float('-inf')
                    
                    for k in range(i, j + 1):
                        box = flattened_tokens[k]["box"]
                        if len(box) == 4:
                            x1, y1, x2, y2 = box
                            min_x = min(min_x, x1)
                            min_y = min(min_y, y1)
                            max_x = max(max_x, x2)
                            max_y = max(max_y, y2)
                    
                    merged_box = [int(min_x), int(min_y), int(max_x), int(max_y)]
                    
                    if return_all:
                        found_boxes.append(merged_box)
                        break
                    else:
                        return merged_box
                
                if len(normalized_window) > len(normalized_target) + 10:
                    break

        if return_all:
            return found_boxes
        return None

    def process_image(self, img_path: str, page_width: int, page_height: int) -> Tuple[Dict, Dict, List[Dict]]:
        """
        Process a single image: OCR -> Entity Classification -> BBox Matching.
        """
        pii_detections = []
        
        # OCR
        
        ocr_dict, extracted_text = self.text_extraction.ocr_image(img_path)
        logger.info(f"OCR Text for {img_path}: {extracted_text[:100]}...")
        
        # Entity Classification
        classified_entities, _ = self.entity_classifier.entity_classifier_and_anonymizer(extracted_text)
        logger.info(f"Classified Entities: {classified_entities.keys()}")

        for entity_name, entities in classified_entities.items():
            for entity in entities:
                entity_value = entity.get("entity_value", "")
                if not entity_value:
                    continue
                
                bbox_pixels = self.find_target_bboxes(entity_value, ocr_dict)
                if bbox_pixels:
                    try:
                        normalized_coords = pixel_bbox_to_normalized(
                            bbox_pixels,
                            page_width,
                            page_height
                        )

                        if validate_normalized_coords(*normalized_coords):
                            pii_detections.append({
                                "type": entity_name,
                                "value": entity_value,
                                "bbox_pixels": bbox_pixels,
                                "normalized_coords": normalized_coords,
                                "confidence": entity.get("confidence_score", 50)
                            })
                    except Exception as e:
                        raise e
        
        return ocr_dict, classified_entities, pii_detections

    def process_document(self, file_path: str, object_id: Any) -> List[int]:
        """
        Process a PDF document: Convert to images -> Process each page -> Save annotations.
        """
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return []

        inserted_ids = []
        document_filename = os.path.basename(file_path)
        
        with open(file_path, 'rb') as f:
            document_hash = hashlib.md5(f.read()).hexdigest()

        try:
            with tempfile.TemporaryDirectory() as temp_path:
                logger.info(f"Converting PDF to images: {file_path}")
                images_from_path = convert_from_path(
                    file_path, 
                    output_folder=temp_path, 
                    fmt="png", 
                    dpi=300,
                    grayscale=True
                )
                
                for page_num, img in enumerate(images_from_path):
                    try:
                        img_path = os.path.join(temp_path, f"page_{page_num}.png")
                        
                        # Ensure grayscale and resize
                        img = img.convert("L")
                        img = self.resize_for_ocr(img, max_size=2000)
                        page_width, page_height = img.size
                        img.save(img_path, "PNG")
                        
                        logger.info(f"Processing page {page_num}...")
                        _, _, pii_detections = self.process_image(img_path, page_width, page_height)
                        logger.info(f"PII detections: {pii_detections}")
                        if pii_detections:
                            try:
                                annot_data, _ = self.annotation_builder.build_from_pii_detections(
                                    pii_detections,
                                    page_num
                                )
                                logger.info(f"Annotations built for page {page_num} {annot_data}")
                                record_id = None
                                record_id = self.db_manager.insert(
                                    annot_data=annot_data,
                                    object_id=object_id,
                                    field_id=382,  # Redaction field
                                    set_id=-1,     # ML-generated
                                    lookup_info1=f"{document_filename}:{document_hash}",
                                    lookup_info2=str(page_num)
                                )
                                
                                if record_id:
                                    inserted_ids.append(record_id)
                                    logger.info(f"Inserted annotations for page {page_num} with Record ID: {record_id}")
                                    
                            except Exception as e:
                                logger.error(f"Error inserting record for page {page_num}: {str(e)}")
                    except Exception as e:
                        logger.error(f"Error processing page {page_num}: {str(e)}")        
        except Exception as e:
            logger.error(f"Error processing document {file_path}: {str(e)}")
            


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process a PDF document for PII redaction.")
    parser.add_argument("pdf_path", help="Path to the PDF file")
    parser.add_argument("--object_id", type=int, default=1001, help="Object ID for database insertion")
    
    args = parser.parse_args()
    
    processor = DocumentProcessor()
    processor.process_document(args.pdf_path, object_id=args.object_id)