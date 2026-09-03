"""
(c) 2025, Daljeet Nandha (w/ Claude 4.0)

Leqi Firmware Encryption/Decryption Tool
Based on reverse engineering analysis of firmware update process

Features:
- Encrypt/decrypt binary files using XOR with key 0xAA
- Generate simulated UART logs with realistic protocol (5A 12 header)
- Parse UART CSV logs to decrypt received firmware
- CRC-16 verification with bit-reversal (matches hardware implementation)

Protocol: Binary packets with 5A 12 header, 128-byte chunks
"""

import argparse
import struct
import sys
from pathlib import Path
import re
import serial
import time

class LeqiFirmwareTool:
    """Tool for handling Leqi scooter firmware encryption/decryption"""
    
    # Constants from reverse engineering
    ENCRYPTION_KEY = 0xAA
    CRC16_POLY = 0x1021         # CRC-16/XMODEM polynomial (for packet validation)
    CRC16_POLY_FIRMWARE = 0x8005  # CRC-16 polynomial for firmware validation (with bit reversal)

    FIRMWARE_OFFSET = 0x80      # Firmware starts at offset 128 in full image
    FIRMWARE_SIZE = 0x9880      # Legacy fallback extraction window (39040 bytes)
    HEADER_TAG = b'EU1\x00'
    HEADER_TAG_OFFSET = 0x0A
    HEADER_SIZE_FIELD_OFFSET = 0x0E
    CRC_START_OFFSET = 0x40
    MIN_FIRMWARE_SIZE = 0x42    # Minimum valid firmware body (66 bytes)
    MIN_PADDING_LENGTH = 500
    ALIGNMENT_BOUNDARY = 128
    
    def __init__(self):
        self.verbose = False
    
    def bit_reverse_8(self, value):
        """Reverse bits in an 8-bit value (matches FUN_000002de)"""
        result = 0
        for i in range(8):
            if value & (1 << i):
                result |= 1 << (7 - i)
        return result & 0xFF
    
    def bit_reverse_16(self, value):
        """Reverse bits in a 16-bit value (matches FUN_000002b2)"""
        result = 0
        for i in range(16):
            if value & (1 << i):
                result |= 1 << (15 - i)
        return result & 0xFFFF
    
    def crc16_with_decryption(self, data):
        """
        Calculate CRC-16 on encrypted firmware (matches crc16WithBitReversal @ 0x00003418)
        This is the CRC algorithm used for firmware validation in processFirmwareUpdateProtocol.

        IMPORTANT: This calculates CRC on the ENCRYPTED data without XOR decryption.
        Uses polynomial 0x8005 with bit reversal on input bytes and final CRC.
        """
        crc = 0xFFFF

        for byte in data:
            # Bit-reverse the byte (NO XOR decryption!)
            reversed_byte = self.bit_reverse_8(byte)

            # XOR into CRC (shifted left 8 bits)
            crc ^= (reversed_byte << 8)

            # Process 8 bits with polynomial 0x8005
            for _ in range(8):
                if crc & 0x8000:
                    crc = ((crc << 1) ^ self.CRC16_POLY_FIRMWARE) & 0xFFFF
                else:
                    crc = ((crc & 0x7FFF) << 1)

        # Final bit-reverse of CRC result
        return self.bit_reverse_16(crc)
    
    def crc16_standard(self, data):
        """
        CRC-16/XMODEM for packet verification.
        Polynomial: 0x1021, Init: 0x0000
        """
        crc = 0x0000

        for byte in data:
            crc ^= byte << 8
            for _ in range(8):
                if crc & 0x8000:
                    crc = ((crc << 1) ^ self.CRC16_POLY) & 0xFFFF
                else:
                    crc = (crc << 1) & 0xFFFF

        return crc & 0xFFFF
    
    def encrypt_data(self, data):
        """Encrypt data using XOR with key 0xAA"""
        return bytes(b ^ self.ENCRYPTION_KEY for b in data)
    
    def decrypt_data(self, data):
        """Decrypt data using XOR with key 0xAA (same as encrypt for XOR)"""
        return self.encrypt_data(data)

    @classmethod
    def parse_header_firmware_size(cls, full_image_data):
        """
        Read the authoritative EU1 firmware body size from a full image header.

        Returns the uint16 LE size field at offset 0x0E when the EU1 tag is present
        and the size plausibly fits within the file, otherwise None.
        """
        if len(full_image_data) < cls.HEADER_SIZE_FIELD_OFFSET + 2:
            return None

        if full_image_data[cls.HEADER_TAG_OFFSET:cls.HEADER_TAG_OFFSET + len(cls.HEADER_TAG)] != cls.HEADER_TAG:
            return None

        firmware_size = struct.unpack(
            '<H',
            full_image_data[cls.HEADER_SIZE_FIELD_OFFSET:cls.HEADER_SIZE_FIELD_OFFSET + 2]
        )[0]

        if firmware_size < cls.MIN_FIRMWARE_SIZE:
            return None

        if len(full_image_data) < cls.FIRMWARE_OFFSET + firmware_size:
            return None

        return firmware_size

    @classmethod
    def extract_firmware_from_image(cls, full_image_data, firmware_size=None):
        """
        Extract the firmware section from a full image file.

        Args:
            full_image_data: Full image data (bytes or bytearray)
            firmware_size: Optional explicit body size. When omitted, reads the EU1
                header size if present, otherwise falls back to FIRMWARE_SIZE.

        Returns:
            firmware_data: The extracted firmware section
        """
        if firmware_size is None:
            firmware_size = cls.parse_header_firmware_size(full_image_data)
        if firmware_size is None:
            firmware_size = cls.FIRMWARE_SIZE

        if len(full_image_data) < cls.FIRMWARE_OFFSET + firmware_size:
            raise ValueError(
                f"Image too small: {len(full_image_data)} bytes. "
                f"Expected at least {cls.FIRMWARE_OFFSET + firmware_size} bytes"
            )

        return full_image_data[cls.FIRMWARE_OFFSET:cls.FIRMWARE_OFFSET + firmware_size]

    def prepare_firmware(self, data):
        """
        Resolve firmware body and size from either a full image or raw firmware body.

        Prefers the EU1 header size field when present, otherwise falls back to
        AA-padding detection on the firmware body (same logic as bwflasher).
        """
        data = bytes(data)
        header_size = self.parse_header_firmware_size(data)
        is_full_image = len(data) > self.FIRMWARE_OFFSET and (
            header_size is not None or len(data) > self.FIRMWARE_SIZE
        )

        if is_full_image:
            encrypted_fw = self.extract_firmware_from_image(data, header_size)
            body_size = header_size if header_size is not None else len(encrypted_fw)
            image_header = data[:self.FIRMWARE_OFFSET]
            image_footer = data[self.FIRMWARE_OFFSET + body_size:]
        else:
            encrypted_fw = data
            image_header = None
            image_footer = None

        if header_size is not None:
            fw_size = header_size
            size_source = "header"
        else:
            fw_size = self.calculate_firmware_size(encrypted_fw)
            size_source = "AA padding"

        return {
            'original': data,
            'encrypted_fw': encrypted_fw,
            'fw_size': fw_size,
            'size_source': size_source,
            'is_full_image': is_full_image,
            'image_header': image_header,
            'image_footer': image_footer,
        }

    @staticmethod
    def reassemble_full_image(encrypted_fw, image_header, image_footer):
        """Insert a patched firmware body back into a full image."""
        return image_header + encrypted_fw + image_footer

    def calculate_firmware_size(self, firmware_data):
        """
        Calculate firmware size by finding end of AA padding in the firmware body.

        Used as a fallback when the EU1 header size field is unavailable.
        """
        data = bytes(firmware_data)
        max_aa_length = 0
        max_aa_end = 0

        i = 0
        while i < len(data):
            if data[i] == 0xAA:
                start = i
                while i < len(data) and data[i] == 0xAA:
                    i += 1
                length = i - start

                if length > max_aa_length and length > self.MIN_PADDING_LENGTH:
                    max_aa_length = length
                    max_aa_end = i
            else:
                i += 1

        if max_aa_end > 0:
            fw_size = ((max_aa_end + self.ALIGNMENT_BOUNDARY - 1) //
                       self.ALIGNMENT_BOUNDARY) * self.ALIGNMENT_BOUNDARY

            if self.verbose:
                print(f"Found {max_aa_length} consecutive AA bytes ending at 0x{max_aa_end:X}")
                print(f"Rounded up to: 0x{fw_size:X}")
            return fw_size

        if self.verbose:
            print("No long AA padding found, using full file size")
        return len(data)

    def patch_firmware_crc(self, firmware_data, fw_size=None):
        """
        Patch the embedded CRC-16 at the end of encrypted firmware

        The firmware validation expects a CRC-16 embedded at bytes [size-2:size].
        This CRC is calculated over the encrypted firmware from offset 0x40 to (size-2)
        using the crc16_with_decryption method.

        Args:
            firmware_data: Encrypted firmware body (not full image)
            fw_size: Optional explicit firmware body size

        Returns:
            bytearray: Firmware with correct CRC patched at the end
        """
        firmware = bytearray(firmware_data)
        if fw_size is None:
            header_size = self.parse_header_firmware_size(firmware)
            if header_size is not None:
                fw_size = header_size
            else:
                fw_size = self.calculate_firmware_size(firmware)

        if fw_size < self.MIN_FIRMWARE_SIZE:
            raise ValueError(f"Firmware too small ({fw_size} bytes), need at least 66 bytes")

        crc_start = self.CRC_START_OFFSET
        crc_end = fw_size - 2
        crc_data = firmware[crc_start:crc_end]

        original_crc = firmware[crc_end:crc_end + 2]
        correct_crc = self.crc16_with_decryption(crc_data)

        firmware[crc_end:fw_size] = struct.pack('>H', correct_crc)

        if self.verbose:
            print(f"Firmware CRC patch:")
            print(f"  CRC calculated over bytes [0x{crc_start:04X}:0x{crc_end:04X}] ({len(crc_data)} bytes)")
            print(f"  Original CRC: {original_crc.hex()}")
            print(f"  Patched CRC: 0x{correct_crc:04X}")
            print(f"  Patched at bytes [0x{crc_end:04X}:0x{fw_size:04X}]")

        return firmware

    def encrypt_file(self, input_file, output_file, patch_crc=True):
        """Encrypt a binary file"""
        print(f"Encrypting {input_file} -> {output_file}")

        # Read input file (raw firmware)
        with open(input_file, 'rb') as f:
            firmware_data = f.read()

        print(f"Original firmware size: {len(firmware_data)} bytes")

        # Encrypt the firmware data (simple XOR with 0xAA)
        encrypted_data = self.encrypt_data(firmware_data)

        # Patch the embedded CRC if requested
        if patch_crc:
            fw_size = self.calculate_firmware_size(encrypted_data)
            encrypted_data = self.patch_firmware_crc(encrypted_data, fw_size)
            validation_crc = self.crc16_with_decryption(encrypted_data[self.CRC_START_OFFSET:fw_size - 2])
            embedded_crc = struct.unpack('>H', encrypted_data[fw_size - 2:fw_size])[0]
            print(f"Embedded CRC (validation): 0x{embedded_crc:04X} (calculated: 0x{validation_crc:04X})")
        else:
            print("Skipping CRC patch (--no-patch-crc specified)")

        # Calculate CRC for information
        encrypted_crc = self.crc16_standard(encrypted_data)
        print(f"Encrypted CRC (full): 0x{encrypted_crc:04X}")

        # Write only the encrypted firmware data (no headers)
        with open(output_file, 'wb') as f:
            f.write(encrypted_data)

        print(f"Encrypted firmware saved: {len(encrypted_data)} bytes")
    
    def verify_file(self, input_file):
        """Verify the embedded CRC in an encrypted firmware file"""
        print(f"Verifying CRC in {input_file}")

        with open(input_file, 'rb') as f:
            firmware_data = f.read()

        prep = self.prepare_firmware(firmware_data)
        encrypted_fw = prep['encrypted_fw']
        fw_size = prep['fw_size']

        print(f"Firmware size: {len(firmware_data)} bytes "
              f"(FW region: 0x{fw_size:X}, source: {prep['size_source']})")

        if fw_size < self.MIN_FIRMWARE_SIZE:
            print("ERROR: Firmware too small for CRC verification")
            return False

        crc_start = self.CRC_START_OFFSET
        crc_end = fw_size - 2
        crc_data = encrypted_fw[crc_start:crc_end]

        embedded_crc = struct.unpack('>H', encrypted_fw[crc_end:crc_end + 2])[0]
        calculated_crc = self.crc16_with_decryption(crc_data)

        print(f"  CRC range: [0x{crc_start:04X}:0x{crc_end:04X}] ({len(crc_data)} bytes)")
        print(f"  Embedded CRC:   0x{embedded_crc:04X}")
        print(f"  Calculated CRC: 0x{calculated_crc:04X}")

        if embedded_crc == calculated_crc:
            print("  ✓ CRC OK")
            return True
        else:
            print("  ✗ CRC MISMATCH")
            return False

    def patch_file(self, input_file, output_file):
        """Patch the embedded CRC in an encrypted firmware file"""
        print(f"Patching CRC in {input_file} -> {output_file}")

        # Read encrypted firmware
        with open(input_file, 'rb') as f:
            firmware_data = f.read()

        prep = self.prepare_firmware(firmware_data)
        encrypted_fw = prep['encrypted_fw']
        fw_size = prep['fw_size']

        print(f"Firmware size: {len(firmware_data)} bytes "
              f"(FW region: 0x{fw_size:X}, source: {prep['size_source']})")

        # Show before CRC
        crc_end = fw_size - 2
        original_crc = struct.unpack('>H', encrypted_fw[crc_end:crc_end + 2])[0]
        calculated_before = self.crc16_with_decryption(encrypted_fw[self.CRC_START_OFFSET:crc_end])
        print(f"  Before: embedded=0x{original_crc:04X}  calculated=0x{calculated_before:04X}  "
              f"{'OK' if original_crc == calculated_before else 'MISMATCH'}")

        # Patch the CRC
        patched_body = self.patch_firmware_crc(encrypted_fw, fw_size)

        # Show after CRC
        new_crc = struct.unpack('>H', patched_body[crc_end:crc_end + 2])[0]
        print(f"  After:  embedded=0x{new_crc:04X}")

        if prep['is_full_image']:
            patched_data = self.reassemble_full_image(
                patched_body, prep['image_header'], prep['image_footer']
            )
        else:
            patched_data = patched_body

        # Write patched firmware
        with open(output_file, 'wb') as f:
            f.write(patched_data)

        print(f"Patched firmware saved: {len(patched_data)} bytes")

    def decrypt_file(self, input_file, output_file):
        """Decrypt an encrypted firmware file (raw data only)"""
        print(f"Decrypting {input_file} -> {output_file}")

        # Read encrypted file
        with open(input_file, 'rb') as f:
            encrypted_data = f.read()

        print(f"Encrypted firmware size: {len(encrypted_data)} bytes")

        # Calculate CRCs for verification
        encrypted_crc = self.crc16_standard(encrypted_data)
        decrypted_crc = self.crc16_with_decryption(encrypted_data)

        print(f"Encrypted CRC: 0x{encrypted_crc:04X}")
        print(f"Decrypted CRC: 0x{decrypted_crc:04X}")

        # Decrypt the data (simple XOR with 0xAA)
        decrypted_data = self.decrypt_data(encrypted_data)

        # Write decrypted firmware
        with open(output_file, 'wb') as f:
            f.write(decrypted_data)

        print(f"Decrypted firmware saved: {len(decrypted_data)} bytes")

    def generate_simulated_uart_log(self, encrypted_firmware_file, output_log_file):
        """
        Generate simulated UART log with firmware update protocol and controller responses

        This creates a realistic CSV log file simulating the complete firmware update
        protocol including controller acknowledgments based on actual captured traffic.
        """
        print(f"Generating simulated UART log from {encrypted_firmware_file} -> {output_log_file}")

        # Controller response templates (from fw_update.csv.log analysis)
        responses = {
            'start': "5A 21 03 01 01 68 26",           # ACK for command 0x03 (Start)
            'data': "5A 21 04 01 01 ED B6",            # ACK for command 0x04 (Data chunk)
            'end': "5A 21 05 01 01 55 A7",             # ACK for command 0x05 (End)
            'telemetry': "5A 21 20 0C 00 00 00 00 00 00 00 18 92 00 00 4A 9A 10",
        }

        # Read encrypted firmware
        with open(encrypted_firmware_file, 'rb') as f:
            file_data = f.read()

        prep = self.prepare_firmware(file_data)
        encrypted_fw = prep['encrypted_fw']
        fw_size = prep['fw_size']
        fw_file_size = len(file_data)
        print(f"Encrypted firmware file size: {fw_file_size} bytes")
        print(f"FWStart size ({prep['size_source']}): 0x{fw_size:X} ({fw_size} bytes)")

        # Calculate CRC-16
        encrypted_crc = self.crc16_standard(encrypted_fw[:fw_size])
        print(f"Encrypted CRC: 0x{encrypted_crc:04X}")

        # Generate UART log
        with open(output_log_file, 'w') as log:
            # Add initial telemetry traffic (realistic background)
            for i in range(3):
                log.write("TX: 5A 12 20 06 40 00 02 00 00 0F 4B 0E\n\n")
                log.write(f"RX: {responses['telemetry']}\n\n")

            # Firmware update start command (0x03)
            start_packet = bytearray([0x5A, 0x12, 0x03, 0x06])
            start_packet.append(0x31)                            # Version/flag byte (payload[0])
            start_packet.append(0x00)                            # Padding (payload[1])
            start_packet.extend(struct.pack('<H', fw_size))      # Firmware size (16-bit LE, payload[2:4])
            start_packet.extend([0x00, 0x00])                    # Padding (payload[4:6])

            # Calculate CRC for start packet
            crc = self.crc16_standard(start_packet)
            start_packet.extend(struct.pack('>H', crc))  # CRC in big-endian

            log.write(f"TX: {' '.join(f'{b:02X}' for b in start_packet)}\n\n")
            log.write(f"RX: {responses['start']}\n\n")

            # Send firmware data in 128-byte chunks (command 0x04)
            # Only send up to fw_size (where AA padding ends), not the entire file
            offset = 0
            chunk_size = 128
            chunk_num = 0

            while offset < fw_size:
                # Get chunk data - only up to fw_size
                chunk_end = min(offset + chunk_size, fw_size)
                chunk_data = encrypted_fw[offset:chunk_end]

                # Pad last chunk to 128 bytes
                if len(chunk_data) < chunk_size:
                    chunk_data = chunk_data + b'\xFF' * (chunk_size - len(chunk_data))

                # Build packet: [5A] [12] [04] [LEN=0x84] [OFFSET32_LE] [DATA×128] [CRC_H] [CRC_L]
                packet = bytearray([0x5A, 0x12, 0x04, 0x84])
                packet.extend(struct.pack('<I', offset))
                packet.extend(chunk_data)

                # Calculate CRC
                crc = self.crc16_standard(packet)
                packet.extend(struct.pack('>H', crc))

                log.write(f"TX: {' '.join(f'{b:02X}' for b in packet)}\n\n")
                log.write(f"RX: {responses['data']}\n\n")

                offset = chunk_end
                chunk_num += 1

                if self.verbose or chunk_num % 10 == 0:
                    print(f"Generated chunk {chunk_num}")

                # Add periodic telemetry (every 10 chunks for realism)
                if chunk_num % 10 == 0:
                    log.write("TX: 5A 12 20 06 40 00 02 00 00 0F 4B 0E\n\n")
                    log.write(f"RX: {responses['telemetry']}\n\n")

            # Firmware update end command (0x05)
            end_packet = bytearray([0x5A, 0x12, 0x05, 0x00])
            crc = self.crc16_standard(end_packet)
            end_packet.extend(struct.pack('>H', crc))

            log.write(f"TX: {' '.join(f'{b:02X}' for b in end_packet)}\n\n")
            log.write(f"RX: {responses['end']}\n\n")

            # Final telemetry
            log.write("TX: 5A 12 20 06 40 00 02 00 00 0F 4B 0E\n\n")
            log.write(f"RX: {responses['telemetry']}\n\n")

        print(f"Generated {chunk_num} firmware chunks")
        print(f"Simulated UART log saved: {output_log_file}")

    def flash_firmware(self, encrypted_firmware_file, port, baudrate=19200, timeout=2.0, log_file=None, encrypt_first=False, patch_crc=True):
        """
        Flash encrypted firmware to controller via serial port

        This performs the complete firmware update protocol:
        1. Send start command (0x03) with firmware size
        2. Send firmware data in 128-byte chunks (0x04)
        3. Send end command (0x05)

        All TX/RX traffic is logged if log_file is specified.

        Args:
            encrypted_firmware_file: Path to encrypted firmware file (or raw firmware if encrypt_first=True)
            port: Serial port path (e.g., '/dev/ttyUSB0' or 'COM3')
            baudrate: Baud rate (default: 19200)
            timeout: Response timeout in seconds
            log_file: Optional path to save TX/RX log (CSV format)
            encrypt_first: If True, encrypt the input file before flashing (default: False)
            patch_crc: If True, patch the embedded CRC before flashing (default: True)

        Returns:
            bool: True if flash succeeded, False otherwise
        """
        print(f"Flashing firmware from {encrypted_firmware_file} to {port}")

        # Read firmware file
        with open(encrypted_firmware_file, 'rb') as f:
            firmware_data = f.read()

        # Encrypt if requested
        if encrypt_first:
            print("Encrypting firmware before flashing...")
            firmware_data = self.encrypt_data(firmware_data)
            print(f"Encrypted to {len(firmware_data)} bytes")

        prep = self.prepare_firmware(firmware_data)
        encrypted_fw = bytearray(prep['encrypted_fw'])
        fw_size = prep['fw_size']

        # Patch embedded CRC if requested (whether encrypted or not)
        if patch_crc:
            print("Patching embedded CRC for firmware validation...")
            encrypted_fw = self.patch_firmware_crc(encrypted_fw, fw_size)
            embedded_crc = struct.unpack('>H', encrypted_fw[fw_size - 2:fw_size])[0]
            validation_crc = self.crc16_with_decryption(
                encrypted_fw[self.CRC_START_OFFSET:fw_size - 2]
            )
            print(f"Embedded CRC: 0x{embedded_crc:04X} (should match validation CRC: 0x{validation_crc:04X})")
            if embedded_crc != validation_crc:
                print("WARNING: CRC mismatch after patching!")
        else:
            print("Skipping CRC patch (--no-patch-crc specified)")

        fw_file_size = len(firmware_data)
        print(f"Firmware file size: {fw_file_size} bytes")
        print(f"FWStart size ({prep['size_source']}): 0x{fw_size:X} ({fw_size} bytes)")

        # Calculate CRC-16
        encrypted_crc = self.crc16_standard(bytes(encrypted_fw[:fw_size]))
        print(f"Packet CRC: 0x{encrypted_crc:04X}")

        # Open log file if specified
        log = None
        session_start_time = None
        if log_file:
            log = open(log_file, 'w')
            session_start_time = time.time()
            print(f"Logging TX/RX to: {log_file}")

        try:
            # Open serial port
            ser = serial.Serial(
                port=port,
                baudrate=baudrate,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=timeout
            )

            print(f"Serial port opened: {port} @ {baudrate} baud")

            # Flush buffers
            ser.reset_input_buffer()
            ser.reset_output_buffer()

            # Helper function to send packet and read response
            def send_and_log(packet, description, custom_timeout=None):
                # Flush any pending data
                ser.reset_input_buffer()

                # Send packet
                tx_time = time.time()
                ser.write(packet)
                ser.flush()  # Ensure data is transmitted
                tx_hex = ' '.join(f'{b:02X}' for b in packet)
                print(f"TX [{description}]: {tx_hex}")
                if log:
                    tx_timestamp = (tx_time - session_start_time) * 1000  # ms since session start
                    log.write(f"[{tx_timestamp:8.2f}ms] TX: {tx_hex}\n\n")

                # Small delay to allow controller to respond
                time.sleep(0.05)

                # Use custom timeout if provided, otherwise use default
                response_timeout = custom_timeout if custom_timeout is not None else timeout

                # Read response
                response = bytearray()
                start_time = time.time()

                # Look for header byte (0x5A)
                while time.time() - start_time < response_timeout:
                    if ser.in_waiting > 0:
                        byte = ser.read(1)
                        if byte[0] == 0x5A:
                            response.append(byte[0])
                            break
                    time.sleep(0.01)

                if len(response) == 0:
                    print(f"RX: <no response - timeout after {response_timeout}s>")
                    print(f"    Buffer state: {ser.in_waiting} bytes waiting")
                    if log:
                        rx_timestamp = (time.time() - session_start_time) * 1000
                        log.write(f"[{rx_timestamp:8.2f}ms] RX: <timeout>\n\n")
                    return None

                # Read rest of response (expected: 7 bytes total for ACK)
                # Format: 5A 21 <CMD> 01 01 <CRC_H> <CRC_L>
                while time.time() - start_time < response_timeout:
                    if ser.in_waiting > 0:
                        byte = ser.read(1)
                        response.append(byte[0])
                        if len(response) >= 7:  # Standard ACK response size
                            break
                    elif len(response) >= 5:  # Minimum valid response
                        # Wait a bit more in case data is still arriving
                        time.sleep(0.02)
                        if ser.in_waiting == 0:
                            break  # No more data coming
                    time.sleep(0.01)

                rx_hex = ' '.join(f'{b:02X}' for b in response)
                rx_time = time.time()
                print(f"RX: {rx_hex} ({len(response)} bytes)")
                if log:
                    rx_timestamp = (rx_time - session_start_time) * 1000
                    log.write(f"[{rx_timestamp:8.2f}ms] RX: {rx_hex}\n\n")

                return bytes(response)

            # STEP 1: Send firmware update start command (0x03)
            print(f"\n[1/3] Sending firmware update start command...")
            start_packet = bytearray([0x5A, 0x12, 0x03, 0x06])
            start_packet.append(0x31)                            # Version/flag byte (payload[0])
            start_packet.append(0x00)                            # Padding (payload[1])
            start_packet.extend(struct.pack('<H', fw_size))      # Firmware size (16-bit LE, payload[2:4])
            start_packet.extend([0x00, 0x00])                    # Padding (payload[4:6])

            # Calculate CRC for start packet
            crc = self.crc16_standard(start_packet)
            start_packet.extend(struct.pack('>H', crc))  # CRC in big-endian

            response = send_and_log(start_packet, "Start")
            if not response:
                print("ERROR: No response to start command")
                return False

            # Verify start ACK (should be 5A 21 03 01 01 ...)
            if len(response) < 5 or response[1] != 0x21 or response[2] != 0x03:
                print(f"ERROR: Invalid start response")
                return False

            print("✓ Start command acknowledged")

            # STEP 2: Send firmware data in 128-byte chunks (command 0x04)
            # Only send up to fw_size (where AA padding ends), not the entire file
            print(f"\n[2/3] Sending firmware data in 128-byte chunks...")
            offset = 0
            chunk_size = 128
            chunk_num = 0
            failed_chunks = 0

            while offset < fw_size:
                # Get chunk data - only up to fw_size
                chunk_end = min(offset + chunk_size, fw_size)
                chunk_data = encrypted_fw[offset:chunk_end]

                # Pad last chunk to 128 bytes
                if len(chunk_data) < chunk_size:
                    chunk_data = chunk_data + b'\xFF' * (chunk_size - len(chunk_data))

                # Build packet: [5A] [12] [04] [LEN=0x84] [OFFSET32_LE] [DATA×128] [CRC_H] [CRC_L]
                packet = bytearray([0x5A, 0x12, 0x04, 0x84])
                packet.extend(struct.pack('<I', offset))
                packet.extend(chunk_data)

                # Calculate CRC
                crc = self.crc16_standard(packet)
                packet.extend(struct.pack('>H', crc))

                chunk_num += 1
                response = send_and_log(packet, f"Chunk {chunk_num} @ 0x{offset:04X}")

                if not response:
                    print(f"WARNING: No response for chunk {chunk_num}")
                    failed_chunks += 1
                elif len(response) < 5 or response[1] != 0x21 or response[2] != 0x04:
                    print(f"WARNING: Invalid response format for chunk {chunk_num}")
                    if self.verbose and response:
                        print(f"    Response bytes: {' '.join(f'{b:02X}' for b in response)}")
                    failed_chunks += 1
                elif len(response) >= 5 and response[4] != 0x01:
                    # Check status byte (byte 4) - should be 0x01 for success
                    # Response format: 5A 21 04 01 [STATUS] [CRC_H] [CRC_L]
                    print(f"ERROR: Chunk {chunk_num} REJECTED by firmware (status=0x{response[4]:02X})")
                    if self.verbose:
                        print(f"    Full response: {' '.join(f'{b:02X}' for b in response)}")
                        print(f"    This indicates firmware validation failure (CRC/flash error)")
                        print(f"    Update flag may be cleared - FWEnd response will likely fail")
                    failed_chunks += 1
                else:
                    # Success - log full response in verbose mode
                    if self.verbose:
                        print(f"    ✓ Chunk {chunk_num} accepted: {' '.join(f'{b:02X}' for b in response)}")

                offset = chunk_end

                if chunk_num % 10 == 0:
                    progress = (offset / fw_size) * 100
                    print(f"Progress: {chunk_num} chunks sent ({progress:.1f}%)")

                # Delay between chunks (measured from real traffic: ~44ms avg)
                time.sleep(0.044)  # 50ms - safe margin based on timing analysis, 44ms in capture

            print(f"✓ Sent {chunk_num} chunks ({failed_chunks} failed)")

            # Give controller time to process last chunk and prepare for end command
            # Analysis shows 690ms gap before first end command in real capture
            print("Waiting for controller to finish processing...")
            time.sleep(0.69)

            # STEP 3: Send firmware update end command (0x05)
            # NOTE: Real capture shows end command needed 4 retries over ~1.5s
            print(f"\n[3/3] Sending firmware update end command...")
            end_packet = bytearray([0x5A, 0x12, 0x05, 0x00])
            crc = self.crc16_standard(end_packet)
            end_packet.extend(struct.pack('>H', crc))

            # Retry end command up to 10 times (controller may be busy writing flash)
            # Use shorter timeout (0.4s) + 100ms delay = ~500ms total between retries
            response = None
            max_retries = 10
            end_timeout = 0.4  # Shorter timeout for end command since we retry

            for attempt in range(1, max_retries + 1):
                if attempt > 1:
                    print(f"Retry {attempt}/{max_retries}...")
                    # Small delay to reach 500ms total between TX
                    # 400ms timeout + 60ms sleep + overhead ≈ 500ms total
                    time.sleep(0.06)

                response = send_and_log(end_packet, f"End (attempt {attempt})", custom_timeout=end_timeout)

                if response and len(response) >= 5:
                    # Check if valid response
                    if response[1] == 0x21 and response[2] == 0x05:
                        break
                    else:
                        print(f"Got response but invalid format")
                        response = None
                elif response:
                    print(f"Got incomplete response ({len(response)} bytes)")
                    response = None

            if not response:
                print(f"ERROR: No valid response to end command after {max_retries} attempts")
                return False

            # Verify end ACK (should be 5A 21 05 01 01 ...)
            if len(response) < 5 or response[1] != 0x21 or response[2] != 0x05:
                print(f"ERROR: Invalid end response")
                return False

            print("✓ End command acknowledged")

            ser.close()

            if failed_chunks > 0:
                print(f"\n⚠ WARNING: {failed_chunks} chunks had invalid/missing responses")
                print("Firmware update may have failed. Verify device functionality.")
                return False

            print(f"\n✓ SUCCESS: Firmware update completed")
            print(f"  Total chunks: {chunk_num}")
            print(f"  Firmware size: {fw_size} bytes")
            return True

        except serial.SerialException as e:
            print(f"ERROR: Serial port error: {e}")
            return False
        except Exception as e:
            print(f"ERROR: Unexpected error: {e}")
            return False
        finally:
            if log:
                log.close()
                print(f"Log saved to: {log_file}")

    def parse_csv_uart_log(self, log_file, output_file, skip_decryption=False):
        """
        Parse CSV UART log with raw protocol packets and decrypt firmware

        Expected format:
        TX: 5A 12 03 06 31 00 00 98 00 00 35 30    (start command)
        TX: 5A 12 04 84 00 00 00 00 D1 01...       (data chunks)

        Packet structure for 0x03 (firmware start):
        [0x5A] [0x12] [0x03] [0x06] [VER] [PAD] [SIZE16_LE] [PAD] [PAD] [CRC_H] [CRC_L]

        Packet structure for 0x04 (firmware data):
        [0x5A] [0x12] [0x04] [LEN] [OFFSET32_LE] [DATA...] [CRC_H] [CRC_L]
        """
        print(f"Parsing CSV UART log {log_file} -> {output_file}")

        firmware_chunks = {}
        total_size = 0
        chunk_count = 0

        with open(log_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()

                # Only process TX lines
                if not line.startswith('TX:'):
                    continue

                # Remove "TX: " prefix and parse hex bytes
                hex_str = line[4:].strip()
                try:
                    packet_bytes = bytes.fromhex(hex_str.replace(' ', ''))
                except ValueError:
                    continue

                # Check if this is a valid packet
                if len(packet_bytes) < 4:
                    continue

                # Check for 5A 12 header
                if packet_bytes[0] != 0x5A or packet_bytes[1] != 0x12:
                    continue

                command = packet_bytes[2]

                # Command 0x03: Start firmware update
                if command == 0x03:
                    if len(packet_bytes) >= 12:
                        # Extract firmware size from start command
                        # Packet: [5A] [12] [03] [06] [VER] [PAD] [SIZE_L] [SIZE_H] [PAD] [PAD] [CRC_H] [CRC_L]
                        # Payload: [VER] [PAD] [SIZE16_LE] [PAD] [PAD]
                        version_byte = packet_bytes[4]
                        total_size = struct.unpack('<H', packet_bytes[6:8])[0]

                        print(f"Found firmware start command at line {line_num}")
                        print(f"  Version/flag byte: 0x{version_byte:02X}")
                        print(f"  Firmware size: 0x{total_size:04X} ({total_size} bytes)")

                # Command 0x04: Firmware data chunk
                elif command == 0x04:
                    if len(packet_bytes) < 12:
                        print(f"WARNING: Packet too short at line {line_num}")
                        continue

                    # Packet structure: [5A] [12] [04] [LEN=0x84] [OFFSET32_LE] [DATA×128] [CRC_H] [CRC_L]
                    # Total: 4 + 132 + 2 = 138 bytes
                    # LEN field (0x84 = 132) includes: offset(4 bytes) + data(128 bytes) = 132 bytes

                    data_len = packet_bytes[3]  # Should be 0x84 = 132

                    # Check packet length
                    expected_len = 4 + data_len + 2  # header + data + CRC
                    if len(packet_bytes) < expected_len:
                        print(f"WARNING: Incomplete packet at line {line_num} (got {len(packet_bytes)}, expected {expected_len})")
                        continue

                    # Extract offset from payload (32-bit little-endian)
                    # This is the file position where this chunk should be written
                    offset = struct.unpack('<I', packet_bytes[4:8])[0]

                    # Extract actual firmware data (skip 4-byte offset prefix in payload)
                    # Payload structure: [OFFSET32_LE] [DATA×128]
                    payload_start = 4  # After header
                    data_start = payload_start + 4  # Skip 32-bit offset (4 bytes)
                    data_size = 128  # Actual firmware data size

                    chunk_data = packet_bytes[data_start:data_start + data_size]

                    # Store chunk
                    firmware_chunks[offset] = chunk_data
                    chunk_count += 1

                    if self.verbose or chunk_count % 50 == 0:
                        print(f"Chunk {chunk_count}: offset 0x{offset:08X}, size {len(chunk_data)} bytes")

        if not firmware_chunks:
            raise ValueError("No firmware data chunks (0x04 commands) found in log file")

        print(f"\nFound {chunk_count} firmware chunks")

        # Reconstruct encrypted firmware from chunks
        print(f"Reconstructing encrypted firmware from {len(firmware_chunks)} chunks...")

        # Sort chunks by offset
        sorted_offsets = sorted(firmware_chunks.keys())
        encrypted_firmware = bytearray()

        expected_offset = 0
        gap_count = 0

        for offset in sorted_offsets:
            if offset != expected_offset:
                gap_size = offset - expected_offset
                print(f"WARNING: Gap of {gap_size} bytes at offset 0x{expected_offset:08X}")
                # Fill gap with zeros
                encrypted_firmware.extend(b'\x00' * gap_size)
                gap_count += 1

            encrypted_firmware.extend(firmware_chunks[offset])
            expected_offset = offset + len(firmware_chunks[offset])

        if gap_count > 0:
            print(f"WARNING: Found {gap_count} gaps in firmware data")

        print(f"Reconstructed encrypted firmware: {len(encrypted_firmware)} bytes")

        # Verify total size if known
        if total_size > 0:
            if len(encrypted_firmware) == total_size:
                print(f"✓ Size matches expected: {total_size} bytes")
            else:
                print(f"WARNING: Size mismatch - reconstructed: {len(encrypted_firmware)}, expected: {total_size}")

        # Calculate CRCs for verification
        encrypted_crc = self.crc16_standard(encrypted_firmware)
        decrypted_crc = self.crc16_with_decryption(encrypted_firmware)

        print(f"\nCRC verification:")
        print(f"  Encrypted CRC: 0x{encrypted_crc:04X}")
        print(f"  Decrypted CRC: 0x{decrypted_crc:04X}")

        if skip_decryption:
            # Save encrypted firmware without decryption
            with open(output_file, 'wb') as f:
                f.write(encrypted_firmware)
            print(f"\n✓ Encrypted firmware saved (no decryption): {len(encrypted_firmware)} bytes")
        else:
            # Decrypt the firmware (simple XOR with 0xAA)
            decrypted_firmware = self.decrypt_data(encrypted_firmware)

            # Save decrypted firmware
            with open(output_file, 'wb') as f:
                f.write(decrypted_firmware)

            print(f"\n✓ Decrypted firmware saved: {len(decrypted_firmware)} bytes")

            # Check for ARM Cortex-M vector table signature
            if len(decrypted_firmware) >= 8:
                stack_ptr = struct.unpack('<I', decrypted_firmware[0:4])[0]
                reset_vector = struct.unpack('<I', decrypted_firmware[4:8])[0]
                print(f"\nFirmware analysis:")
                print(f"  Stack pointer: 0x{stack_ptr:08X}")
                print(f"  Reset vector:  0x{reset_vector:08X}")

                # ARM Cortex-M reset vector should be odd (Thumb mode) and in flash range
                if reset_vector & 1 and 0x08000000 <= reset_vector <= 0x08010000:
                    print(f"  ✓ Valid ARM Cortex-M firmware detected")
                else:
                    print(f"  ⚠ Warning: May not be valid ARM Cortex-M firmware")

def main():
    parser = argparse.ArgumentParser(
        description='Leqi Firmware Encryption/Decryption Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Encrypt firmware (raw data) - automatically patches CRC
  python leqi_fw_tool.py enc firmware.bin firmware_encrypted.bin

  # Encrypt firmware without CRC patch
  python leqi_fw_tool.py enc firmware.bin firmware_encrypted.bin --no-patch-crc

  # Verify embedded CRC in encrypted firmware
  python leqi_fw_tool.py verify firmware_encrypted.bin

  # Patch CRC in already-encrypted firmware
  python leqi_fw_tool.py patch firmware_encrypted.bin firmware_patched.bin

  # Decrypt firmware (raw data)
  python leqi_fw_tool.py dec firmware_encrypted.bin firmware_decrypted.bin

  # Flash encrypted firmware via serial port (automatically patches CRC)
  python leqi_fw_tool.py flash firmware_encrypted.bin /dev/ttyUSB0 --log flash_log.csv

  # Flash without CRC patching (NOT recommended - will likely fail)
  python leqi_fw_tool.py flash firmware_encrypted.bin /dev/ttyUSB0 --no-patch-crc

  # Flash raw (unencrypted) firmware (will encrypt and patch CRC)
  python leqi_fw_tool.py flash firmware.bin /dev/ttyUSB0 --encrypt

  # Flash with custom baud rate and timeout
  python leqi_fw_tool.py flash firmware_encrypted.bin COM3 -b 19200 -t 5.0

  # Generate simulated UART log (CSV format with realistic protocol)
  python leqi_fw_tool.py sim_log firmware_encrypted.bin simulated_uart.log

  # Parse CSV UART log (raw protocol packets) and decrypt firmware
  python leqi_fw_tool.py csv_parse fw_update.csv.log firmware_decrypted.bin

  # Parse CSV UART log and save encrypted firmware (no decryption)
  python leqi_fw_tool.py csv_parse fw_update.csv.log firmware_encrypted.bin --no-decrypt

Note: The protocol uses binary packets (5A 12 header) with 128-byte chunks,
not AT-style commands. CRC patching is enabled by default for all operations
that write firmware (enc, flash) to ensure firmware validation succeeds.
        """
    )

    parser.add_argument('operation', choices=['enc', 'dec', 'patch', 'verify', 'csv_parse', 'sim_log', 'flash'],
                       help='Operation to perform')
    parser.add_argument('input_file', help='Input file path (or serial port for flash)')
    parser.add_argument('output_file', nargs='?', help='Output file path (not used for flash/verify)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('-b', '--baudrate', type=int, default=19200,
                       help='Baud rate for serial communication (default: 19200)')
    parser.add_argument('-t', '--timeout', type=float, default=2.0,
                       help='Serial port timeout in seconds (default: 2.0)')
    parser.add_argument('--log', type=str, default=None,
                       help='Log file path for TX/RX traffic (flash operation only)')
    parser.add_argument('--encrypt', action='store_true',
                       help='Encrypt the firmware before flashing (flash operation only)')
    parser.add_argument('--no-decrypt', action='store_true',
                       help='Save encrypted firmware without decryption (csv_parse only)')
    parser.add_argument('--patch-crc', dest='patch_crc', action='store_true', default=True,
                       help='Patch embedded firmware CRC (default: enabled)')
    parser.add_argument('--no-patch-crc', dest='patch_crc', action='store_false',
                       help='Skip patching embedded firmware CRC')

    args = parser.parse_args()

    # Validate arguments based on operation
    if args.operation == 'flash':
        # For flash: input_file is firmware, output_file is serial port
        if not args.output_file:
            parser.error("flash operation requires both firmware file and serial port")
        firmware_file = args.input_file
        serial_port = args.output_file
    elif args.operation == 'verify':
        pass  # verify only needs input_file
    elif args.operation in ['enc', 'dec', 'patch', 'csv_parse', 'sim_log']:
        # For other operations: both input and output are files
        if not args.output_file:
            parser.error(f"{args.operation} operation requires both input and output files")

    tool = LeqiFirmwareTool()
    tool.verbose = args.verbose

    try:
        if args.operation == 'enc':
            tool.encrypt_file(args.input_file, args.output_file, patch_crc=args.patch_crc)

        elif args.operation == 'dec':
            tool.decrypt_file(args.input_file, args.output_file)

        elif args.operation == 'patch':
            tool.patch_file(args.input_file, args.output_file)

        elif args.operation == 'verify':
            if not tool.verify_file(args.input_file):
                sys.exit(1)

        elif args.operation == 'flash':
            success = tool.flash_firmware(
                firmware_file,
                serial_port,
                baudrate=args.baudrate,
                timeout=args.timeout,
                log_file=args.log,
                encrypt_first=args.encrypt,
                patch_crc=args.patch_crc
            )
            if not success:
                print("\nFirmware flash FAILED", file=sys.stderr)
                sys.exit(1)

        elif args.operation == 'csv_parse':
            tool.parse_csv_uart_log(args.input_file, args.output_file, skip_decryption=args.no_decrypt)

        elif args.operation == 'sim_log':
            tool.generate_simulated_uart_log(args.input_file, args.output_file)

        print("\nOperation completed successfully!")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
