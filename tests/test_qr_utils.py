import unittest

from qrshield.qr_utils import decode_qr_image, generate_qr_png


class TestQRImageTools(unittest.TestCase):
    def test_generated_qr_decodes_to_original_payload(self):
        payload = "https://example.com/qrshield-demo"
        image_bytes = generate_qr_png(payload)
        self.assertEqual(decode_qr_image(image_bytes), [payload])

    def test_empty_qr_payload_is_rejected(self):
        with self.assertRaises(ValueError):
            generate_qr_png(" ")


if __name__ == "__main__":
    unittest.main()
