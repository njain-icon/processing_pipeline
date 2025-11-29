"""
Coordinate Converter Module

Converts pixel-based bounding boxes to normalized percentage coordinates
for iCONECT annotation format.

iCONECT requires coordinates as percentages (0.0-1.0) rather than pixels:
- 0.0 = left/top edge of page
- 1.0 = right/bottom edge of page
- 0.5 = middle of page

This allows annotations to scale correctly across different page sizes.
"""

from typing import Tuple, List


def pixel_bbox_to_normalized(
    bbox_pixels: List[int],
    page_width: int,
    page_height: int
) -> Tuple[float, float, float, float]:
    """
    Convert pixel bounding box to normalized percentage coordinates.

    Args:
        bbox_pixels: Bounding box as [x1, y1, x2, y2] in pixels
                    (x1, y1) = top-left corner
                    (x2, y2) = bottom-right corner
        page_width: Page width in pixels
        page_height: Page height in pixels

    Returns:
        Tuple of (left, top, width, height) as percentages (0.0-1.0)
        where:
            left: X position as percentage of page width (0.0-1.0)
            top: Y position as percentage of page height (0.0-1.0)
            width: Width as percentage of page width (0.0-1.0)
            height: Height as percentage of page height (0.0-1.0)

    Example:
        >>> # Bbox at (100, 200) to (350, 230) on 1000x1400 page
        >>> pixel_bbox_to_normalized([100, 200, 350, 230], 1000, 1400)
        (0.1, 0.14285714285714285, 0.25, 0.021428571428571432)

        # This means:
        # - Starts 10% from left edge (0.1)
        # - Starts 14.3% from top edge (0.143)
        # - Spans 25% of page width (0.25)
        # - Spans 2.1% of page height (0.021)
    """
    if len(bbox_pixels) != 4:
        raise ValueError(f"Expected bbox with 4 coordinates [x1, y1, x2, y2], got {len(bbox_pixels)}")

    if page_width <= 0 or page_height <= 0:
        raise ValueError(f"Invalid page dimensions: {page_width}x{page_height}")

    x1, y1, x2, y2 = bbox_pixels

    # Ensure coordinates are in correct order
    if x2 < x1:
        x1, x2 = x2, x1
    if y2 < y1:
        y1, y2 = y2, y1

    # Convert to percentages (0.0-1.0)
    left = x1 / page_width
    top = y1 / page_height
    width = (x2 - x1) / page_width
    height = (y2 - y1) / page_height

    # Clamp values to valid range [0.0, 1.0]
    left = max(0.0, min(1.0, left))
    top = max(0.0, min(1.0, top))
    width = max(0.0, min(1.0, width))
    height = max(0.0, min(1.0, height))

    return (left, top, width, height)


def get_page_dimensions_from_image(image) -> Tuple[int, int]:
    """
    Get page dimensions from a PIL Image object.

    Args:
        image: PIL Image object

    Returns:
        Tuple of (width, height) in pixels
    """
    return image.size  # Returns (width, height)


def validate_normalized_coords(left: float, top: float, width: float, height: float) -> bool:
    """
    Validate that normalized coordinates are within valid range.

    Args:
        left: X position (0.0-1.0)
        top: Y position (0.0-1.0)
        width: Width (0.0-1.0)
        height: Height (0.0-1.0)

    Returns:
        True if all coordinates are valid, False otherwise
    """
    # Check all values are in [0.0, 1.0]
    if not (0.0 <= left <= 1.0 and 0.0 <= top <= 1.0):
        return False
    if not (0.0 <= width <= 1.0 and 0.0 <= height <= 1.0):
        return False

    # Check that box doesn't exceed page boundaries
    if left + width > 1.0:
        return False
    if top + height > 1.0:
        return False

    # Check that box has positive dimensions
    if width <= 0.0 or height <= 0.0:
        return False

    return True


def convert_multiple_bboxes(
    bboxes: List[List[int]],
    page_width: int,
    page_height: int
) -> List[Tuple[float, float, float, float]]:
    """
    Convert multiple pixel bounding boxes to normalized coordinates.

    Args:
        bboxes: List of bounding boxes, each as [x1, y1, x2, y2] in pixels
        page_width: Page width in pixels
        page_height: Page height in pixels

    Returns:
        List of tuples (left, top, width, height) as percentages
    """
    normalized_boxes = []

    for bbox in bboxes:
        try:
            normalized = pixel_bbox_to_normalized(bbox, page_width, page_height)

            # Validate coordinates
            if validate_normalized_coords(*normalized):
                normalized_boxes.append(normalized)
            else:
                print(f"Warning: Invalid normalized coordinates for bbox {bbox}: {normalized}")
        except Exception as e:
            print(f"Error converting bbox {bbox}: {e}")

    return normalized_boxes


if __name__ == "__main__":
    # Example usage and testing
    print("Coordinate Converter Test")
    print("=" * 60)

    # Test case 1: SSN detection on standard letter size
    print("\nTest 1: SSN on letter-sized page (2550x3300 pixels at 300 DPI)")
    bbox = [382, 825, 632, 855]  # Example SSN location
    page_w, page_h = 2550, 3300

    left, top, width, height = pixel_bbox_to_normalized(bbox, page_w, page_h)
    print(f"  Pixel bbox: {bbox}")
    print(f"  Page size: {page_w}x{page_h}")
    print(f"  Normalized: left={left:.4f}, top={top:.4f}, width={width:.4f}, height={height:.4f}")
    print(f"  Valid: {validate_normalized_coords(left, top, width, height)}")

    # Test case 2: Multiple boxes
    print("\nTest 2: Multiple PII detections")
    bboxes = [
        [100, 200, 350, 230],   # Name
        [400, 500, 550, 520],   # Phone
        [200, 800, 450, 830]    # Email
    ]

    normalized = convert_multiple_bboxes(bboxes, page_w, page_h)
    for i, (bbox, norm) in enumerate(zip(bboxes, normalized), 1):
        print(f"  Box {i}: {bbox} -> left={norm[0]:.4f}, top={norm[1]:.4f}, "
              f"width={norm[2]:.4f}, height={norm[3]:.4f}")

    # Test case 3: Edge cases
    print("\nTest 3: Edge cases")

    # Box at edges
    edge_bbox = [0, 0, page_w, page_h]
    norm = pixel_bbox_to_normalized(edge_bbox, page_w, page_h)
    print(f"  Full page box: {norm}")
    print(f"  Valid: {validate_normalized_coords(*norm)}")

    # Reversed coordinates (should auto-correct)
    reversed_bbox = [632, 855, 382, 825]
    norm = pixel_bbox_to_normalized(reversed_bbox, page_w, page_h)
    print(f"  Reversed coords: {reversed_bbox} -> {norm}")
    print(f"  Valid: {validate_normalized_coords(*norm)}")

    print("\n" + "=" * 60)
    print("All tests completed!")
