import unittest
from src.encryption.aes_handler import AESHandler

class TestEncryption(unittest.TestCase):
    def setUp(self):
        """Set up test environment"""
        self.encryption = AESHandler()
        self.test_data = b"Test data for encryption"
        
    def test_key_generation(self):
        """Test encryption key generation"""
        # Generate key
        key_id, key = self.encryption.generate_key()
        
        # Verify key format
        self.assertIsInstance(key_id, str)
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), 32)  # AES-256 key length
        
        # Verify key is stored
        self.assertIn(key_id, self.encryption._keys)
        self.assertEqual(self.encryption._keys[key_id], key)
        
    def test_encryption_decryption(self):
        """Test data encryption and decryption"""
        # Generate key
        key_id, _ = self.encryption.generate_key()
        
        # Encrypt data
        encrypted = self.encryption.encrypt(self.test_data, key_id)
        self.assertIsNotNone(encrypted)
        self.assertNotEqual(encrypted, self.test_data)
        
        # Decrypt data
        decrypted = self.encryption.decrypt(encrypted, key_id)
        self.assertEqual(decrypted, self.test_data)
        
    def test_invalid_key(self):
        """Test encryption/decryption with invalid keys"""
        # Try to encrypt with invalid key
        encrypted = self.encryption.encrypt(self.test_data, "invalid_key")
        self.assertIsNone(encrypted)
        
        # Generate valid key and encrypt
        key_id, _ = self.encryption.generate_key()
        encrypted = self.encryption.encrypt(self.test_data, key_id)
        
        # Try to decrypt with invalid key
        decrypted = self.encryption.decrypt(encrypted, "invalid_key")
        self.assertIsNone(decrypted)
        
    def test_multiple_keys(self):
        """Test handling multiple encryption keys"""
        # Generate multiple keys
        key_id1, _ = self.encryption.generate_key()
        key_id2, _ = self.encryption.generate_key()
        
        # Encrypt same data with different keys
        encrypted1 = self.encryption.encrypt(self.test_data, key_id1)
        encrypted2 = self.encryption.encrypt(self.test_data, key_id2)
        
        # Verify different ciphertexts
        self.assertNotEqual(encrypted1, encrypted2)
        
        # Decrypt with correct keys
        decrypted1 = self.encryption.decrypt(encrypted1, key_id1)
        decrypted2 = self.encryption.decrypt(encrypted2, key_id2)
        
        # Verify both decrypt to original
        self.assertEqual(decrypted1, self.test_data)
        self.assertEqual(decrypted2, self.test_data)
        
        # Try cross-decryption (should fail)
        cross1 = self.encryption.decrypt(encrypted1, key_id2)
        cross2 = self.encryption.decrypt(encrypted2, key_id1)
        self.assertIsNone(cross1)
        self.assertIsNone(cross2)
        
    def test_data_integrity(self):
        """Test encrypted data integrity"""
        # Generate key and encrypt
        key_id, _ = self.encryption.generate_key()
        encrypted = self.encryption.encrypt(self.test_data, key_id)
        
        # Modify encrypted data
        modified = bytearray(encrypted)
        modified[0] ^= 1  # Flip one bit
        
        # Try to decrypt modified data
        decrypted = self.encryption.decrypt(bytes(modified), key_id)
        self.assertIsNone(decrypted)  # Should fail integrity check 