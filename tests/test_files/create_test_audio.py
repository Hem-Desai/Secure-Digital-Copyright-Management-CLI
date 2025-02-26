import wave
import numpy as np

# Audio parameters
duration = 3  # seconds
sample_rate = 44100  # Hz
frequency = 440  # Hz (A4 note)

# Generate sine wave
t = np.linspace(0, duration, int(sample_rate * duration))
audio_data = np.sin(2 * np.pi * frequency * t)

# Scale to 16-bit integers
audio_data = (audio_data * 32767).astype(np.int16)

# Create WAV file
with wave.open('tests/test_files/test.wav', 'w') as wav_file:
    # Set parameters
    wav_file.setnchannels(1)  # Mono
    wav_file.setsampwidth(2)  # 2 bytes per sample (16 bits)
    wav_file.setframerate(sample_rate)
    
    # Write data
    wav_file.writeframes(audio_data.tobytes())

print("Created test WAV file successfully") 