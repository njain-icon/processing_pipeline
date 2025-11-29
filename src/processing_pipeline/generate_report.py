import sys
import os
import pandas as pd
import tempfile
import time
import argparse
import glob
import traceback
from pdf2image import convert_from_path
from PIL import Image

# Add the project root to sys.path to allow imports
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, "../../../"))
sys.path.append(project_root)

from ocr_pipeline.ocr.ocr import TextExtraction
from classifier.entity_classifier.entity_classifier import EntityClassifier
from classifier.log import get_logger

import logging

logger = logging.getLogger("generate_report")
handler = logging.FileHandler("generate_report.log")
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Initialize classifiers
entity_classifier = EntityClassifier(countries=["US"])
text_extraction_obj = TextExtraction()

from PIL import Image

def resize_for_ocr(img, min_size=800, max_size=1600):
    #img = Image.open(img_path)
    w, h = img.size
    max_dim = max(w, h)

    # Large → downscale
    if max_dim > max_size:
        scale = max_size / max_dim

    # Small → upscale
    elif max_dim < min_size:
        scale = min_size / max_dim

    else:
        return img  # no resize needed

    new_w = int(w * scale)
    new_h = int(h * scale)

    img = img.resize((new_w, new_h), Image.LANCZOS)
    return img


def process_folder_to_excel(folder_path, output_excel_path):
    data = []
    pdf_files = glob.glob(os.path.join(folder_path, "*.pdf"))
    if not pdf_files:
        logger.warning(f"No PDF files found in {folder_path}")
        return

    for pdf_no, pdf_path in enumerate(pdf_files):
        file_name = os.path.basename(pdf_path)
        logger.info(f"Processing file: {file_name}")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            images_from_path = []
            try:
                images_from_path = convert_from_path(
                    pdf_path, 
                    output_folder=temp_dir, 
                    fmt="png", 
                    dpi=300,
                    grayscale=True
                )
            except Exception as e:
                error_msg = f"Error converting PDF: {str(e)}"
                logger.error(f"{error_msg}")
                data.append({
                    'file_name': file_name,
                    'page_no': 0,
                    'extracted_text': "",
                    'extracted_entity': "",
                    'ocr_time_seconds': 0,
                    'entity_time_seconds': 0,
                    'error': error_msg
                })
                continue

            for i, img in enumerate(images_from_path):
                page_num = i + 1
                img_path = os.path.join(temp_dir, f"page_{i}.png")
                
                error_msg = ""
                extracted_text = ""
                classified_entities = ""
                ocr_duration = 0
                entity_duration = 0

                try:
                    # Convert and save image
                    img = img.convert("L")
                    #img.save(img_path, "PNG")
                    img = resize_for_ocr(img)
                    img.save(img_path, "PNG")
                    
                    logger.info(f"Processing  {pdf_no+1}/{len(pdf_files)} file | File Name - {file_name} | Page No - {page_num}/{len(images_from_path)}...")
                    
                    # OCR
                    ocr_start_time = time.time()
                    try:
                        _, extracted_text = text_extraction_obj.ocr_image(img_path)
                    except Exception as e:
                        error_msg += f"OCR Error: {str(e)}; "
                        logger.error(f"  Error during OCR on page {page_num}: {e}")
                    ocr_end_time = time.time()
                    ocr_duration = ocr_end_time - ocr_start_time

                    # Entity Classification
                    if extracted_text:
                        entity_start_time = time.time()
                        try:
                            classified_entities, _ = entity_classifier.entity_classifier_and_anonymizer(extracted_text)
                        except Exception as e:
                            error_msg += f"Entity Classification Error: {str(e)}; "
                            logger.error(f"  Error during classification on page {page_num}: {e}")
                            classified_entities = "Error"
                        entity_end_time = time.time()
                        entity_duration = entity_end_time - entity_start_time
                
                except Exception as e:
                    error_msg += f"Page Processing Error: {str(e)}; "
                    logger.error(f"  Error processing page {page_num}: {e}")

                # Append to data list
                data.append({
                    'file_name': file_name,
                    'page_no': page_num,
                    'extracted_text': extracted_text,
                    'extracted_entity': str(classified_entities),
                    'ocr_time_seconds': ocr_duration,
                    'entity_time_seconds': entity_duration,
                    'error': error_msg.strip()
                })
            
    # Create DataFrame and save to Excel
    if data:
        df = pd.DataFrame(data)
        df.to_excel(output_excel_path, index=False)
        logger.info(f"Report generated at {output_excel_path}")
    else:
        logger.info("No data processed.")

if __name__ == "__main__":
    process_folder_to_excel("/Users/nishanjain/Downloads/", "report.xlsx")
